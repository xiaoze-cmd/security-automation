#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
from pathlib import Path


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-ip-file", required=True)
    parser.add_argument("--flows-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    host_ip = Path(args.host_ip_file).read_text(encoding="utf-8").strip().split()[0]
    flows_path = Path(args.flows_file)
    outbound_public: set[str] = set()

    if flows_path.exists():
        with flows_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                src = (row.get("ip.src") or "").strip()
                dst = (row.get("ip.dst") or "").strip()
                tcp_port = (row.get("tcp.dstport") or "").strip()
                udp_port = (row.get("udp.dstport") or "").strip()
                if src != host_ip or not is_public_ip(dst):
                    continue
                port = tcp_port or udp_port or "unknown"
                proto = "tcp" if tcp_port else "udp" if udp_port else "ip"
                outbound_public.add(f"{dst}:{port}/{proto}")

    summary = {
        "host_ip": host_ip,
        "public_outbound_endpoints": sorted(outbound_public),
        "public_outbound_count": len(outbound_public),
        "status": "pass" if not outbound_public else "review",
        "note": "Host-level packet summary. If other processes run on the test host, review false positives manually.",
    }

    Path(args.output).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
