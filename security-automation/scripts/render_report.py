#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def read_exit_code(path: Path) -> str:
    if not path.exists():
        return "missing"
    return path.read_text(encoding="utf-8").strip() or "missing"


def dependency_check_section(source_dir: Path) -> list[str]:
    report = read_json(source_dir / "dependency-check-report.json")
    exit_code = read_exit_code(source_dir / "dependency-check.exit")
    lines = ["## OWASP Dependency-Check", f"- Exit code: `{exit_code}`"]
    if not report:
        lines.append("- No parseable JSON report was generated.")
        return lines

    dependencies = report.get("dependencies", [])
    vulnerable = 0
    vulnerabilities = 0
    for dependency in dependencies:
        vuln_list = dependency.get("vulnerabilities") or []
        if vuln_list:
            vulnerable += 1
            vulnerabilities += len(vuln_list)

    lines.extend(
        [
            f"- Dependencies scanned: `{len(dependencies)}`",
            f"- Vulnerable dependencies: `{vulnerable}`",
            f"- Vulnerabilities found: `{vulnerabilities}`",
        ]
    )
    return lines


def sonar_section(source_dir: Path) -> list[str]:
    summary = read_json(source_dir / "sonar-summary.json")
    exit_code = read_exit_code(source_dir / "sonar.exit")
    lines = ["## SonarQube", f"- Exit code: `{exit_code}`"]
    if not summary or "component" not in summary:
        lines.append("- No parseable Sonar summary was generated. This usually means `SONAR_TOKEN` is missing or the query failed.")
        return lines

    measures = {
        item["metric"]: item.get("value", "")
        for item in summary["component"].get("measures", [])
    }
    lines.extend(
        [
            f"- Quality Gate: `{measures.get('alert_status', 'unknown')}`",
            f"- Vulnerabilities: `{measures.get('vulnerabilities', 'unknown')}`",
            f"- Bugs: `{measures.get('bugs', 'unknown')}`",
            f"- Code smells: `{measures.get('code_smells', 'unknown')}`",
        ]
    )
    return lines


def sbom_section(source_dir: Path) -> list[str]:
    exit_code = read_exit_code(source_dir / "sbom.exit")
    json_files = sorted(path.name for path in source_dir.glob("*.json") if "dependency-check" not in path.name)
    lines = ["## SBOM", f"- Exit code: `{exit_code}`"]
    if not json_files:
        lines.append("- No SBOM file was found in the artifacts.")
    else:
        lines.append(f"- Generated files: `{', '.join(json_files)}`")
    lines.append("- If Dependency-Track is unavailable, keep the SBOM artifacts and upload them later.")
    return lines


def runtime_section(runtime_dir: Path) -> list[str]:
    if not runtime_dir.exists():
        return ["## Runtime Scans", "- Runtime scans were not executed in this run."]

    port_summary = read_json(runtime_dir / "port-summary.json")
    pcap_summary = read_json(runtime_dir / "pcap-summary.json")
    runtime_exit = read_exit_code(runtime_dir / "runtime-remote.exit")
    lines = ["## Runtime Scans"]
    lines.append(f"- Remote execution status: `{runtime_exit}`")

    if port_summary:
        unexpected = port_summary.get("unexpected_open_ports", [])
        lines.append(f"- Port whitelist status: `{port_summary.get('status', 'unknown')}`")
        lines.append(f"- Open ports detected: `{len(port_summary.get('open_ports', []))}`")
        if unexpected:
            rendered = ", ".join(str(item["port"]) for item in unexpected)
            lines.append(f"- Unexpected open ports: `{rendered}`")
        else:
            lines.append("- Unexpected open ports: `none`")
    else:
        lines.append("- Port scan summary is missing.")

    if pcap_summary:
        endpoints = pcap_summary.get("public_outbound_endpoints", [])
        lines.append(f"- Packet capture summary: `{pcap_summary.get('status', 'unknown')}`")
        if endpoints:
            lines.append(f"- Public outbound endpoints: `{', '.join(endpoints)}`")
        else:
            lines.append("- Public outbound endpoints: `none`")
        lines.append(f"- Note: {pcap_summary.get('note', '')}")
    else:
        lines.append("- Packet capture summary is missing.")

    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-ref", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    runtime_dir = Path(args.runtime_dir)
    lines = [
        "# Release Security Report",
        "",
        f"- Git Ref: `{args.git_ref}`",
        f"- Workflow Run: {args.run_url}",
        "",
        "## Scope",
        "- This report is generated before release and focuses on source scanning, dependency scanning, SBOM generation, port checks, and packet-capture summaries.",
        "- The default mode is report-only. It does not block releases automatically.",
        "",
    ]
    lines.extend(dependency_check_section(source_dir))
    lines.append("")
    lines.extend(sonar_section(source_dir))
    lines.append("")
    lines.extend(sbom_section(source_dir))
    lines.append("")
    lines.extend(runtime_section(runtime_dir))
    lines.append("")
    lines.extend(
        [
            "## Follow-up",
            "- Review OWASP and Sonar findings manually and confirm false positives.",
            "- Review public outbound endpoints together with other processes running on the test host.",
            "- Add automatic Dependency-Track upload and result retrieval after the platform is available again.",
        ]
    )

    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
