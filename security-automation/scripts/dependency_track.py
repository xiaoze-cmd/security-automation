#!/usr/bin/env python3
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class DependencyTrackError(RuntimeError):
    pass


class DependencyTrackClient:
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.token: str | None = None

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        expect_json: bool = True,
        allow_statuses: set[int] | None = None,
    ):
        url = f"{self.base_url}{path}"
        request_headers = headers.copy() if headers else {}
        if self.token:
            request_headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                body = response.read()
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as error:
            status = error.code
            body = error.read()
            response_headers = dict(error.headers.items())
            if not allow_statuses or status not in allow_statuses:
                message = body.decode("utf-8", errors="ignore") or error.reason
                raise DependencyTrackError(f"{method} {path} failed with status {status}: {message}") from error
        except urllib.error.URLError as error:
            raise DependencyTrackError(f"{method} {path} failed: {error.reason}") from error

        if expect_json:
            decoded = body.decode("utf-8", errors="ignore")
            if not decoded:
                return status, response_headers, None
            try:
                return status, response_headers, json.loads(decoded)
            except json.JSONDecodeError as error:
                raise DependencyTrackError(f"{method} {path} returned non-JSON response") from error

        return status, response_headers, body

    def login(self) -> str:
        form = urllib.parse.urlencode(
            {
                "username": self.username,
                "password": self.password,
            }
        ).encode("utf-8")
        _, _, body = self._request(
            "POST",
            "/api/v1/user/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form,
            expect_json=False,
        )
        token = body.decode("latin1", errors="ignore").strip()
        if not token:
            raise DependencyTrackError("Login returned an empty token")
        self.token = token
        return token

    def get_self(self) -> dict:
        _, _, data = self._request("GET", "/api/v1/user/self")
        return data

    def lookup_project(self, name: str, version: str) -> dict | None:
        query = urllib.parse.urlencode({"name": name, "version": version})
        status, _, body = self._request(
            "GET",
            f"/api/v1/project/lookup?{query}",
            expect_json=False,
            allow_statuses={404},
        )
        if status == 404:
            return None
        decoded = body.decode("utf-8", errors="ignore")
        return json.loads(decoded)

    def create_project(self, name: str, version: str, classifier: str, is_latest: bool) -> dict:
        payload = {
            "name": name,
            "version": version,
            "classifier": classifier,
            "isLatest": is_latest,
        }
        _, _, data = self._request(
            "PUT",
            "/api/v1/project",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode("utf-8"),
        )
        return data

    def upload_bom(self, project_uuid: str, project_name: str, project_version: str, bom_path: Path) -> str:
        encoded_bom = base64.b64encode(bom_path.read_bytes()).decode("ascii")
        payload = {
            "project": project_uuid,
            "projectName": project_name,
            "projectVersion": project_version,
            "bom": encoded_bom,
        }
        _, _, data = self._request(
            "PUT",
            "/api/v1/bom",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode("utf-8"),
        )
        token = data.get("token") if isinstance(data, dict) else None
        if not token:
            raise DependencyTrackError("BOM upload did not return a processing token")
        return token

    def is_token_processing(self, token: str) -> bool:
        _, _, data = self._request("GET", f"/api/v1/event/token/{token}")
        if not isinstance(data, dict) or "processing" not in data:
            raise DependencyTrackError("Token status response is invalid")
        return bool(data["processing"])

    def get_project_metrics(self, project_uuid: str) -> dict:
        _, _, data = self._request("GET", f"/api/v1/metrics/project/{project_uuid}/current")
        return data


def write_summary(output_path: Path, summary: dict) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--project-version", required=True)
    parser.add_argument("--project-classifier", default="APPLICATION")
    parser.add_argument("--project-is-latest", action="store_true")
    parser.add_argument("--create-project", action="store_true")
    parser.add_argument("--skip-upload", action="store_true")
    parser.add_argument("--sbom-path")
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--poll-timeout", type=int, default=900)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output_path = Path(args.output)
    summary = {
        "status": "error",
        "base_url": args.base_url,
        "project": {
            "name": args.project_name,
            "version": args.project_version,
            "classifier": args.project_classifier,
            "is_latest": args.project_is_latest,
        },
        "authentication": {},
        "sbom": {},
        "metrics": None,
        "errors": [],
    }

    try:
        if not args.skip_upload and not args.sbom_path:
            raise DependencyTrackError("--sbom-path is required unless --skip-upload is used")

        client = DependencyTrackClient(
            base_url=args.base_url,
            username=args.username,
            password=args.password,
        )

        token = client.login()
        current_user = client.get_self()
        summary["authentication"] = {
            "username": current_user.get("username"),
            "fullname": current_user.get("fullname"),
            "teams": [team.get("name") for team in current_user.get("teams", [])],
        }
        summary["token_received"] = bool(token)

        project = client.lookup_project(args.project_name, args.project_version)
        project_created = False
        if project is None:
            if not args.create_project:
                raise DependencyTrackError(
                    f"Project {args.project_name}@{args.project_version} was not found and project creation is disabled"
                )
            project = client.create_project(
                args.project_name,
                args.project_version,
                args.project_classifier,
                args.project_is_latest,
            )
            project_created = True

        project_uuid = project.get("uuid")
        if not project_uuid:
            raise DependencyTrackError("Project response does not include a UUID")

        summary["project"].update(
            {
                "uuid": project_uuid,
                "created": project_created,
                "active": project.get("active"),
                "last_bom_import": project.get("lastBomImport"),
            }
        )

        if args.skip_upload:
            summary["status"] = "pass"
            try:
                summary["metrics"] = client.get_project_metrics(project_uuid)
            except DependencyTrackError as error:
                summary["errors"].append(str(error))
            write_summary(output_path, summary)
            return 0

        bom_path = Path(args.sbom_path)
        if not bom_path.is_file():
            raise DependencyTrackError(f"SBOM file not found: {bom_path}")

        upload_token = client.upload_bom(project_uuid, args.project_name, args.project_version, bom_path)
        summary["sbom"] = {
            "path": str(bom_path),
            "size_bytes": bom_path.stat().st_size,
            "upload_token": upload_token,
            "poll_interval_seconds": args.poll_interval,
            "poll_timeout_seconds": args.poll_timeout,
        }

        start = time.time()
        attempts = 0
        while True:
            attempts += 1
            processing = client.is_token_processing(upload_token)
            if not processing:
                summary["sbom"]["processing_complete"] = True
                summary["sbom"]["poll_attempts"] = attempts
                summary["sbom"]["elapsed_seconds"] = round(time.time() - start, 2)
                break
            if time.time() - start >= args.poll_timeout:
                summary["sbom"]["processing_complete"] = False
                summary["sbom"]["poll_attempts"] = attempts
                summary["sbom"]["elapsed_seconds"] = round(time.time() - start, 2)
                raise DependencyTrackError("Timed out waiting for BOM processing to complete")
            time.sleep(args.poll_interval)

        summary["metrics"] = client.get_project_metrics(project_uuid)
        summary["status"] = "pass"
        write_summary(output_path, summary)
        return 0
    except Exception as error:
        summary["errors"].append(str(error))
        write_summary(output_path, summary)
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
