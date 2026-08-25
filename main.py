from __future__ import annotations

import argparse
<<<<<<< HEAD
from contextlib import redirect_stdout
from io import StringIO
import json
import sys
import textwrap
=======
import json
import sys
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
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
<<<<<<< HEAD
DEFAULT_JSON_FILE = str(Path(DEFAULT_REPORT_DIR) / "scan.json")
DEFAULT_PDF_FILE = str(Path(DEFAULT_REPORT_DIR) / "scan.pdf")
=======
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f


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


<<<<<<< HEAD
def render_report_text(data: Any) -> str:
    reports = data if isinstance(data, list) else [data]
    sections: list[str] = []

    for index, report in enumerate(reports, start=1):
        buffer = StringIO()
        with redirect_stdout(buffer):
            if len(reports) > 1:
                print("\n" + "=" * 78)
                print(f"BATCH REPORT {index}/{len(reports)}")
                print("=" * 78)
            print_integrated_report(report)
        sections.append(buffer.getvalue().strip())

    return "\n\n".join(sections) + "\n"


def _escape_pdf_text(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _pdf_safe_text(value: str) -> str:
    return value.encode("latin-1", "replace").decode("latin-1")


def _paginate_text(
    text: str,
    line_width: int,
    lines_per_page: int,
) -> list[list[str]]:
    wrapper = textwrap.TextWrapper(
        width=line_width,
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=True,
        break_on_hyphens=False,
    )
    lines: list[str] = []

    for raw_line in text.splitlines():
        expanded = raw_line.expandtabs(4)
        if not expanded:
            lines.append("")
            continue
        lines.extend(wrapper.wrap(expanded) or [""])

    if not lines:
        lines = ["No report content."]

    return [
        lines[index : index + lines_per_page]
        for index in range(0, len(lines), lines_per_page)
    ]


def _build_pdf_bytes(text: str) -> bytes:
    page_width = 612
    page_height = 792
    margin = 36
    font_size = 9
    line_height = 12
    line_width = int((page_width - (2 * margin)) / (font_size * 0.6))
    lines_per_page = int((page_height - (2 * margin)) / line_height)
    pages = _paginate_text(text, line_width, lines_per_page)

    objects: list[bytes] = []
    page_object_numbers = [
        4 + (page_index * 2) for page_index in range(len(pages))
    ]
    kids = " ".join(f"{object_number} 0 R" for object_number in page_object_numbers)

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii")
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    for page_index, lines in enumerate(pages):
        page_object_number = 4 + (page_index * 2)
        content_object_number = page_object_number + 1
        page_object = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Resources << /Font << /F1 3 0 R >> >> "
            f"/Contents {content_object_number} 0 R >>"
        )
        objects.append(page_object.encode("ascii"))

        commands = [
            "BT",
            f"/F1 {font_size} Tf",
            f"{line_height} TL",
            f"{margin} {page_height - margin} Td",
        ]
        for line in lines:
            safe_line = _escape_pdf_text(_pdf_safe_text(line))
            commands.append(f"({safe_line}) Tj")
            commands.append("T*")
        commands.append("ET")

        stream = "\n".join(commands).encode("latin-1", "replace")
        stream_object = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"\nendstream"
        )
        objects.append(stream_object)

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    startxref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{startxref}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(pdf)


def save_pdf(data: Any, filename: str) -> Path:
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(_build_pdf_bytes(render_report_text(data)))
    return output_path


=======
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
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
<<<<<<< HEAD
        nargs="?",
        const=DEFAULT_JSON_FILE,
        metavar="JSON_FILE",
        help=f"Save report JSON. Defaults to {DEFAULT_JSON_FILE}.",
    )
    parser.add_argument(
        "--pdf",
        dest="pdf_file",
        nargs="?",
        const=DEFAULT_PDF_FILE,
        metavar="PDF_FILE",
        help=f"Save report PDF. Defaults to {DEFAULT_PDF_FILE}.",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Analyze the completed scan locally with Ollama.",
    )
    parser.add_argument(
        "--ai-model",
        default="qwen3.5:4b",
        help="Local Ollama model to use (default: qwen3.5:4b).",
    )
    parser.add_argument(
        "--ai-url",
        default="http://127.0.0.1:11434",
        help="Ollama API base URL (default: http://127.0.0.1:11434).",
=======
        help=f"Save report JSON. Defaults to {DEFAULT_REPORT_DIR}/scan.json.",
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
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
<<<<<<< HEAD
            report = run_integrated_scan(
                require_target(target),
                ai_enabled=args.ai,
                ai_model=args.ai_model,
                ai_url=args.ai_url,
            )
=======
            report = run_integrated_scan(require_target(target))
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
            print_integrated_report(report)
            reports.append(report)

        if args.json_file:
            output_path = save_json(reports, args.json_file)
            print(f"\n[+] JSON reports saved to: {output_path}")
<<<<<<< HEAD
        if args.pdf_file:
            output_path = save_pdf(reports, args.pdf_file)
            print(f"\n[+] PDF reports saved to: {output_path}")
=======
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
        return

    target = args.target or input("Enter target IP, domain, or URL: ")
    target = require_target(target)

<<<<<<< HEAD
    report = run_integrated_scan(
        target,
        ai_enabled=args.ai,
        ai_model=args.ai_model,
        ai_url=args.ai_url,
    )
=======
    report = run_integrated_scan(target)
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
    print_integrated_report(report)

    if args.json_file:
        output_path = save_json(report, args.json_file)
        print(f"\n[+] JSON report saved to: {output_path}")
<<<<<<< HEAD
    if args.pdf_file:
        output_path = save_pdf(report, args.pdf_file)
        print(f"\n[+] PDF report saved to: {output_path}")
=======
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f


if __name__ == "__main__":
    main()
