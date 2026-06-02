#!/usr/bin/env python3
"""
Scan the repository for IP/CIDR ranges and host domains, then update sanitization.json.

Usage:
  python3 scripts/discover_sanitization.py                 # preview on stdout
  python3 scripts/discover_sanitization.py --write         # update sanitization.json
  python3 scripts/discover_sanitization.py --write-example # update sanitization.json.example
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sanitize_common import (  # noqa: E402
    CONFIG_EXAMPLE_FILENAME,
    CONFIG_FILENAME,
    build_updated_config,
    scan_repo_for_domains,
    scan_repo_for_networks,
    write_json,
)


def _repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return Path(out.stdout.strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return Path.cwd().resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Auto-discover subnets and domains; update sanitization.json"
    )
    parser.add_argument("--write", action="store_true", help=f"Write {CONFIG_FILENAME}")
    parser.add_argument(
        "--write-example",
        action="store_true",
        help=f"Write {CONFIG_EXAMPLE_FILENAME}",
    )
    parser.add_argument("--scan-dir", type=Path, default=None, help="Directory to scan")
    args = parser.parse_args()

    root = args.scan_dir.resolve() if args.scan_dir else _repo_root()
    if not root.is_dir():
        print(f"discover_sanitization: not a directory: {root}", file=sys.stderr)
        return 1

    networks = scan_repo_for_networks(root)
    domains = scan_repo_for_domains(root)
    config = build_updated_config(root)

    print(f"Scanned {root}", file=sys.stderr)
    print(f"  Networks: {len(networks)}  Domains: {len(domains)}", file=sys.stderr)
    for rule in config.get("subnet_rules", []):
        print(f"  {rule['actual_cidr']} → {rule['dummy_cidr']}", file=sys.stderr)

    if args.write:
        write_json(root / CONFIG_FILENAME, config)
        print(f"Wrote {root / CONFIG_FILENAME}", file=sys.stderr)
    elif args.write_example:
        example = dict(config)
        example["description"] = (
            f"Copy to {CONFIG_FILENAME} (gitignored). "
            "Refresh subnets: python3 scripts/discover_sanitization.py --write"
        )
        example["salt"] = "change-me-to-a-random-string"
        write_json(root / CONFIG_EXAMPLE_FILENAME, example)
        print(f"Wrote {root / CONFIG_EXAMPLE_FILENAME}", file=sys.stderr)
    else:
        sys.stdout.write(json.dumps(config, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
