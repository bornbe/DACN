"""
Giao diện dòng lệnh CLI - Issue #4.2.

Ví dụ:
    python scanner.py -u http://127.0.0.1:8080 -d 2 -m headers,csrf -o report.json
    python scanner.py -u http://example.local -m all -o report.pdf --no-db
"""

from __future__ import annotations

import argparse
import sys
import threading
from typing import Any

from core.engine.scan_context import ScanContext
from core.engine.scan_engine import ScanEngine, normalize_modules
from core.scanners import ALL_MODULES
from services.report_service import SUPPORTED_FORMATS, export_report, render_markdown_table

BAR_WIDTH = 30


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="OWASP Automated Pentest Scanner - công cụ quét lỗ hổng web tự động.",
    )
    parser.add_argument("-u", "--url", required=True, help="URL mục tiêu (http:// hoặc https://).")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Độ sâu crawler (mặc định 2).")
    parser.add_argument(
        "-m",
        "--modules",
        default="all",
        help=f"Module quét, phân tách bằng dấu phẩy: all, {', '.join(ALL_MODULES)} (mặc định all).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help=f"Tệp báo cáo xuất ra; định dạng theo đuôi tệp ({', '.join(SUPPORTED_FORMATS)}).",
    )
    parser.add_argument("--max-pages", type=int, default=100, help="Số trang crawl tối đa (mặc định 100).")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout mỗi request, giây (mặc định 10).")
    parser.add_argument("--delay", type=float, default=0.0, help="Độ trễ giữa các request, giây (rate limit).")
    parser.add_argument("--no-db", action="store_true", help="Không lưu kết quả vào cơ sở dữ liệu.")
    parser.add_argument("--quiet", action="store_true", help="Ẩn thanh tiến trình.")
    return parser


class ProgressBar:
    """Thanh tiến trình văn bản trên stderr, tự cập nhật theo sự kiện của Engine."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and sys.stderr.isatty()
        self._lock = threading.Lock()

    def __call__(self, event: dict[str, Any]) -> None:
        kind = event["type"]
        if kind == "warning":
            self._write_line(f"[!] {event['message']}")
        elif kind == "finding":
            f = event["finding"]
            self._write_line(f"[+] [{f['severity']}] {f['vuln_name']} - {f['target_url']}")
        elif kind == "progress" and self.enabled:
            percent = event["percent"]
            filled = int(BAR_WIDTH * percent / 100)
            bar = "#" * filled + "-" * (BAR_WIDTH - filled)
            message = event["message"][:50].ljust(50)
            with self._lock:
                sys.stderr.write(f"\r[{bar}] {percent:3d}% {event['phase']:<9} {message}")
                sys.stderr.flush()

    def _write_line(self, text: str) -> None:
        with self._lock:
            if self.enabled:
                sys.stderr.write("\r" + " " * 110 + "\r")
            sys.stderr.write(text + "\n")
            sys.stderr.flush()

    def finish(self) -> None:
        if self.enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    modules = normalize_modules([m for m in args.modules.split(",")])
    invalid = [m for m in modules if m not in ALL_MODULES]
    if invalid:
        parser.error(f"Module không hợp lệ: {', '.join(invalid)}. Hợp lệ: all, {', '.join(ALL_MODULES)}")
    if args.depth < 0 or args.max_pages < 1 or args.timeout < 1 or args.delay < 0:
        parser.error("depth >= 0, max-pages >= 1, timeout >= 1, delay >= 0.")
    if args.output:
        ext = args.output.rsplit(".", 1)[-1].lower() if "." in args.output else ""
        if ext not in SUPPORTED_FORMATS:
            parser.error(f"Đuôi tệp báo cáo phải là một trong: {', '.join(SUPPORTED_FORMATS)}")
    return modules


def main(argv: list[str] | None = None) -> int:
    # Đảm bảo in được tiếng Việt trên console Windows
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)
    modules = _validate_args(args, parser)

    db_session = None
    if not args.no_db:
        try:
            from models.base import get_session_factory, init_db

            engine = init_db()
            db_session = get_session_factory(engine)()
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Không khởi tạo được CSDL, tiếp tục không lưu: {exc}", file=sys.stderr)

    progress = ProgressBar(enabled=not args.quiet)
    context = ScanContext(
        target_url=args.url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        modules=modules,
        request_delay=args.delay,
        persist=db_session is not None,
        on_event=progress,
    )

    print(f"[*] Bắt đầu quét {args.url} (depth={args.depth}, modules={','.join(modules)})", file=sys.stderr)
    try:
        report = ScanEngine(context, db_session=db_session).run()
    finally:
        progress.finish()
        if db_session is not None:
            db_session.close()

    data = report.to_dict()
    print()
    print(f"## Kết quả quét: {data['target_url']}  [{data['status']}]")
    print(f"Thời gian: {data['duration_seconds']}s | Endpoints: {data['summary'].get('total_endpoints', 0)} "
          f"| Findings: {data['summary'].get('total_findings', 0)}")
    print()
    print(render_markdown_table(data["findings"]))

    if args.output:
        try:
            path = export_report(data, args.output)
            print(f"\n[+] Đã xuất báo cáo: {path}")
        except Exception as exc:  # noqa: BLE001
            print(f"\n[!] Xuất báo cáo thất bại: {exc}", file=sys.stderr)
            return 1

    if report.status == "NO_MODULES":
        print(f"[!] {report.message}", file=sys.stderr)
        print("[!] Hãy chọn module khả dụng (ví dụ: -m headers,csrf).", file=sys.stderr)
        return 2
    if report.status == "FAILED":
        print(f"[!] Quét thất bại: {report.error_message}", file=sys.stderr)
        return 1
    if report.status == "CANCELLED":
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
