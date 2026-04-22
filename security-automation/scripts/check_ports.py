#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


PORT_RE = re.compile(r"^(?P<port>\d+)/(?:tcp|udp)\s+open\b(?P<rest>.*)$")


def parse_allowed(path: Path) -> set[int]:
    allowed: set[int] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
      line = raw.strip()
      if not line or line.startswith("#"):
          continue
      if "-" in line:
          start_text, end_text = line.split("-", 1)
          start = int(start_text)
          end = int(end_text)
          allowed.update(range(start, end + 1))
      else:
          allowed.add(int(line))
    return allowed


def parse_nmap(path: Path) -> list[dict]:
    open_ports: list[dict] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        match = PORT_RE.match(line)
        if not match:
            continue
        port = int(match.group("port"))
        rest = match.group("rest").strip()
        tokens = rest.split()
        service = tokens[0] if tokens else ""
        version = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        open_ports.append(
            {
                "port": port,
                "service": service,
                "version": version,
                "raw": line,
            }
        )
    return sorted(open_ports, key=lambda item: item["port"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nmap", required=True)
    parser.add_argument("--allowed", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    allowed = parse_allowed(Path(args.allowed))
    open_ports = parse_nmap(Path(args.nmap))
    unexpected = [item for item in open_ports if item["port"] not in allowed]

    summary = {
        "allowed_port_count": len(allowed),
        "open_ports": open_ports,
        "unexpected_open_ports": unexpected,
        "status": "pass" if not unexpected else "review",
    }

    Path(args.output).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
