from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from config.scanner_config import DEFAULT_REPORT_DIR
from core.reporter import print_integrated_report
from core.validators import require_target


DEPENDENCY_HINTS = {
    "nmap": "python-nmap",
    "bs4": "beautifulsoup4",
    "requests": "requests",
}


def load_targets(filename: str) -> list[str]:
    targets: list[str] = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            target = line.strip()
            if target and not target.startswith("#"):
                targets.append(target)

    return targets


def save_json(data: Any, filename: str) -> Path:
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VulnScope Lite integrated vulnerability scanner"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Authorized target IP, hostname, or HTTP(S) URL.",
    )
    parser.add_argument(
        "--target-file",
        help="File containing one authorized target per line.",
    )
    parser.add_argument(
        "--json",
        dest="json_file",
        help=f"Save report JSON. Defaults to {DEFAULT_REPORT_DIR}/scan.json.",
    )
    return parser


def load_integrated_scanner():
    try:
        from core.scanner import run_integrated_scan
    except ModuleNotFoundError as error:
        package_name = DEPENDENCY_HINTS.get(error.name, error.name)
        print(
            f"[ERROR] Missing required Python package: {package_name}",
            file=sys.stderr,
        )
        print(
            "Install project dependencies with: "
            "python -m pip install -r requirements.txt",
            file=sys.stderr,
        )
        if error.name == "nmap":
            print(
                "Recon also needs the Nmap application installed and available "
                "in your system PATH.",
                file=sys.stderr,
            )
        sys.exit(1)

    return run_integrated_scan


def disable_request_warnings() -> None:
    try:
        import requests
    except ModuleNotFoundError:
        return

    requests.packages.urllib3.disable_warnings()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    disable_request_warnings()
    run_integrated_scan = load_integrated_scanner()

    if args.target_file:
        try:
            targets = load_targets(args.target_file)
        except OSError as error:
            print(f"[ERROR] Cannot read target file: {error}", file=sys.stderr)
            sys.exit(1)

        if not targets:
            print("[ERROR] Target file contains no targets.", file=sys.stderr)
            sys.exit(1)

        reports = []
        for index, target in enumerate(targets, start=1):
            print(f"\n[{index}/{len(targets)}] {target}")
            report = run_integrated_scan(require_target(target))
            print_integrated_report(report)
            reports.append(report)

        if args.json_file:
            output_path = save_json(reports, args.json_file)
            print(f"\n[+] JSON reports saved to: {output_path}")
        return

    target = args.target or input("Enter target IP, domain, or URL: ")
    target = require_target(target)

    report = run_integrated_scan(target)
    print_integrated_report(report)

    if args.json_file:
        output_path = save_json(report, args.json_file)
        print(f"\n[+] JSON report saved to: {output_path}")


if __name__ == "__main__":
    main()
