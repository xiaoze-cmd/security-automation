# security-automation

Release security automation templates for TimechoDB.

## Included

- GitHub Actions workflow for pre-release security reports
- Port whitelist configuration
- Helper scripts for port checks, packet-capture summaries, and report rendering
- Reference documents used to derive the automation flow

## Main Files

- `.github/workflows/release-security-report.yml`
- `security-automation/config/allowed-ports.txt`
- `security-automation/scripts/check_ports.py`
- `security-automation/scripts/summarize_endpoints.py`
- `security-automation/scripts/render_report.py`
- `security-automation/README.md`
