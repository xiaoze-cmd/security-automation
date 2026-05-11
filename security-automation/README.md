# Security Automation Template

This template builds a pre-release security report with these stages:

- `SonarQube` source analysis
- `OWASP Dependency-Check` dependency analysis
- `SBOM` generation
- `Dependency-Track` project lookup/create and SBOM upload
- post-deploy `nmap` port scan and `tcpdump/tshark` packet summary

## Workflow

- `.github/workflows/release-security-report.yml`

The workflow is triggered manually with `workflow_dispatch`. It is intended for release-candidate validation before a release decision.

## Required GitHub Secrets

- `SONAR_TOKEN`
- `OSS_INDEX_USERNAME`
- `OSS_INDEX_PASSWORD`
- `DEPENDENCY_TRACK_USERNAME`
- `DEPENDENCY_TRACK_PASSWORD`
- `RUNTIME_SCAN_SSH_USER`
- `RUNTIME_SCAN_SSH_KEY`
- `RUNTIME_SCAN_KNOWN_HOSTS` optional

## Recommended GitHub Variables

- `SONAR_HOST_URL`
- `SONAR_PROJECT_KEY`
- `SONAR_PROJECT_NAME`
- `DEPENDENCY_TRACK_BASE_URL`
- `DEPENDENCY_TRACK_PROJECT_NAME`
- `DEPENDENCY_TRACK_PROJECT_VERSION`
- `DEPENDENCY_TRACK_PROJECT_CLASSIFIER`
- `DEPENDENCY_TRACK_CREATE_PROJECT`
- `DEPENDENCY_TRACK_PROJECT_IS_LATEST`

## Dependency-Track Notes

The current server expects:

- UI host: `https://sbom.infra.timecho.com`
- API host: `https://sbom-api.infra.timecho.com`
- login endpoint: `POST /api/v1/user/login`
- login content type: `application/x-www-form-urlencoded`

The helper script is:

- `security-automation/scripts/dependency_track.py`

It can:

- log in and obtain a bearer token
- look up a project by exact name and version
- create the project when enabled
- upload a generated SBOM
- poll asynchronous processing status
- fetch project metrics for the report

## Runtime Scan Prerequisites

- the target host is deployed and running the candidate build
- `nmap` is installed on the target host
- `tcpdump` is installed on the target host
- the SSH user can execute `sudo nmap` and `sudo tcpdump`

## Port Whitelist

- `security-automation/config/allowed-ports.txt`

Default whitelist:

- `6667`
- `9091`
- `9092`
- `10710-10760`

## Current Limits

- packet summaries are host-level and may include traffic from other processes on the same machine
- the workflow is report-only by default and does not block releases
