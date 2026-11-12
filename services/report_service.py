"""
Dịch vụ xuất báo cáo quét (TXT / JSON / PDF) và dựng bảng kết quả dạng Markdown.
Dùng chung cho CLI (Issue #4.2); có thể mở rộng cho API tải báo cáo (Issue #6.2).
"""

from __future__ import annotations

import json
import logging
import os
<<<<<<< Updated upstream
from pathlib import Path
from typing import Any
=======
import re
import unicodedata
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any
from xml.sax.saxutils import escape

from config.config import BASE_DIR, Config

if TYPE_CHECKING:
    from models.scan_job import CrawledEndpoint, ScanSession
    from models.vulnerability import VulnerabilityFinding
>>>>>>> Stashed changes

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SUPPORTED_FORMATS = ("txt", "json", "pdf")
<<<<<<< Updated upstream
=======
API_REPORT_FORMATS = ("txt", "pdf")

# Loại bỏ các ký tự điều khiển XML không hợp lệ trước khi đưa vào ReportLab Paragraph
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_VIETNAMESE_MAP = str.maketrans({"đ": "d", "Đ": "D"})


def _transliterate_ascii(text: str) -> str:
    """
    Chuyển chuỗi tiếng Việt có dấu sang ASCII không dấu khi hệ thống không có font TrueType Unicode
    (tránh lỗi hiển thị ô vuông đen trên font Type1 Helvetica mặc định của ReportLab).
    """
    mapped = text.translate(_VIETNAMESE_MAP)
    decomposed = unicodedata.normalize("NFKD", mapped)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch)).encode("ascii", "replace").decode("ascii")


def _sanitize_xml_text(value: Any, *, ascii_fallback: bool = False) -> str:
    """
    Làm sạch ký tự điều khiển XML và escape các thực thể HTML/XML (`&`, `<`, `>`, `'`, `"`).
    Nếu `ascii_fallback=True`, chuyển ký tự tiếng Việt sang ASCII trước khi escape.
    """
    text = "" if value is None else str(value)
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    if ascii_fallback:
        cleaned = _transliterate_ascii(cleaned)
    return escape(cleaned, {'"': "&quot;", "'": "&#39;"})
>>>>>>> Stashed changes


def _cell(value: Any, limit: int = 80) -> str:
    """Làm sạch giá trị để đặt vào ô bảng Markdown."""
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


<<<<<<< Updated upstream
=======
def _compute_normalized_summary(report: dict[str, Any]) -> dict[str, Any]:
    """
    Đảm bảo thống kê mức độ nghiêm trọng (`severity_counts`) và `total_findings` luôn được
    tính nhất quán từ danh sách `findings` thực tế cho cả TXT và PDF, tránh lệch với summary cũ.
    """
    raw_summary = dict(report.get("summary") or {}) if isinstance(report.get("summary"), dict) else {}
    findings = report.get("findings")
    if isinstance(findings, list):
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for item in findings:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "INFO").upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1
        total_findings = len(findings)
    else:
        stored_counts = raw_summary.get("severity_counts") or {}
        counts = {sev: int(stored_counts.get(sev, 0) or 0) for sev in SEVERITY_ORDER}
        total_findings = int(raw_summary.get("total_findings", sum(counts.values())) or 0)

    endpoints = report.get("endpoints")
    endpoint_count = len(endpoints) if isinstance(endpoints, list) else 0
    total_endpoints = max(int(raw_summary.get("total_endpoints", 0) or 0), endpoint_count)
    pages_crawled = int(raw_summary.get("pages_crawled", total_endpoints) or 0)

    return {
        "pages_crawled": pages_crawled,
        "total_endpoints": total_endpoints,
        "total_findings": total_findings,
        "severity_counts": counts,
    }


def build_session_report(
    scan: "ScanSession",
    findings: list["VulnerabilityFinding"] | None = None,
    endpoints: list["CrawledEndpoint"] | None = None,
) -> dict[str, Any]:
    """
    Tổng hợp dữ liệu báo cáo chuẩn hóa từ thực thể ScanSession, CrawledEndpoint và VulnerabilityFinding
    đã lưu trong CSDL (chỉ lấy dữ liệu thuộc phiên quét đó).
    """
    finding_items = findings if findings is not None else list(scan.findings or [])
    endpoint_items = endpoints if endpoints is not None else list(scan.endpoints or [])

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    serialized_findings: list[dict[str, Any]] = []
    for item in finding_items:
        sev = (item.severity or "INFO").upper()
        if sev not in severity_counts:
            sev = "INFO"
        severity_counts[sev] += 1
        serialized_findings.append(
            {
                "id": item.id,
                "vuln_name": item.vuln_type,
                "vuln_type": item.vuln_type,
                "severity": sev,
                "target_url": item.target_url,
                "parameter": item.param,
                "param": item.param,
                "payload": item.payload,
                "evidence": item.evidence,
                "cwe_id": item.cwe_id,
                "owasp_category": item.owasp_category,
                "remediation": item.remediation,
            }
        )

    stored_summary = dict(scan.summary_stats) if isinstance(scan.summary_stats, dict) else {}
    total_endpoints = max(int(stored_summary.get("total_endpoints", 0) or 0), len(endpoint_items))
    pages_crawled = int(stored_summary.get("pages_crawled", total_endpoints) or 0)

    duration_seconds = 0.0
    if scan.start_time and scan.end_time:
        duration_seconds = round(max((scan.end_time - scan.start_time).total_seconds(), 0.0), 2)

    target_url = scan.target.url if scan.target else ""
    target_name = scan.target.name if scan.target else ""

    return {
        "session_id": scan.id,
        "target_name": target_name,
        "target_url": target_url,
        "max_depth": scan.max_depth,
        "status": scan.status,
        "progress": scan.progress,
        "modules": list(scan.modules_enabled or []),
        "skipped_modules": {},
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "duration_seconds": duration_seconds,
        "summary": {
            "pages_crawled": pages_crawled,
            "total_endpoints": total_endpoints,
            "total_findings": len(serialized_findings),
            "severity_counts": severity_counts,
        },
        "error_message": scan.error_message,
        "message": None,
        "endpoints": [ep.to_dict() for ep in endpoint_items],
        "findings": serialized_findings,
    }


>>>>>>> Stashed changes
def render_markdown_table(findings: list[dict[str, Any]]) -> str:
    """Bảng Markdown tóm tắt các lỗ hổng."""
    if not findings:
        return "_Không phát hiện lỗ hổng nào._"
    lines = [
        "| # | Severity | Vulnerability | URL | Parameter | CWE |",
        "|---|----------|---------------|-----|-----------|-----|",
    ]
    for idx, f in enumerate(findings, 1):
        lines.append(
            f"| {idx} | {_cell(f['severity'])} | {_cell(f['vuln_name'], 60)} | "
            f"{_cell(f['target_url'], 60)} | {_cell(f.get('parameter'), 30)} | {_cell(f.get('cwe_id'), 12)} |"
        )
    return "\n".join(lines)


def _summary_lines(report: dict[str, Any]) -> list[str]:
<<<<<<< Updated upstream
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
    lines = [
        f"Target        : {report.get('target_url')}",
=======
    summary = _compute_normalized_summary(report)
    counts = summary["severity_counts"]
    lines: list[str] = []
    if report.get("session_id") is not None:
        lines.append(f"Session ID    : #{report.get('session_id')}")
    lines.append(f"Target        : {report.get('target_url')}")
    if report.get("max_depth") is not None:
        lines.append(f"Scope Depth   : max_depth={report.get('max_depth')}")
    lines += [
>>>>>>> Stashed changes
        f"Status        : {report.get('status')}",
        f"Start / End   : {report.get('start_time')} -> {report.get('end_time')}",
        f"Duration      : {report.get('duration_seconds')} s",
        f"Modules       : {', '.join(report.get('modules', [])) or '-'}",
        f"Pages crawled : {summary.get('pages_crawled', 0)}",
        f"Endpoints     : {summary.get('total_endpoints', 0)}",
        f"Findings      : {summary.get('total_findings', 0)}  ("
        + ", ".join(f"{sev}={counts.get(sev, 0)}" for sev in SEVERITY_ORDER)
        + ")",
    ]
    for module, reason in report.get("skipped_modules", {}).items():
        lines.append(f"Skipped       : {module} ({reason})")
    if report.get("message"):
        lines.append(f"Message       : {report['message']}")
    if report.get("error_message"):
        lines.append(f"Error         : {report['error_message']}")
    return lines


def render_text(report: dict[str, Any]) -> str:
    """Báo cáo TXT: thông tin phiên, bảng tóm tắt và chi tiết từng lỗ hổng."""
    out = ["=" * 78, "OWASP AUTOMATED PENTEST REPORT", "=" * 78, *_summary_lines(report), ""]
    findings = report.get("findings", [])
    out += ["SUMMARY TABLE", "-" * 78, render_markdown_table(findings), "", "DETAILS", "-" * 78]
    for idx, f in enumerate(findings, 1):
        out += [
            f"[{idx}] [{f['severity']}] {f['vuln_name']}",
            f"    URL         : {f['target_url']}",
            f"    Parameter   : {f.get('parameter') or '-'}",
            f"    Payload     : {f.get('payload') or '-'}",
            f"    CWE / OWASP : {f.get('cwe_id') or '-'} / {f.get('owasp_category') or '-'}",
            f"    Evidence    : {f.get('evidence') or '-'}",
            f"    Remediation : {f.get('remediation') or '-'}",
            "",
        ]
    return "\n".join(out)


def _get_unicode_font_candidates() -> list[Path]:
    """Danh sách đường dẫn font TrueType Unicode hỗ trợ tiếng Việt trên các hệ điều hành."""
    windir = os.environ.get("WINDIR", r"C:\Windows")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    bundled_dir = BASE_DIR / "static" / "fonts"

    candidates: list[Path] = [
        bundled_dir / "DejaVuSans.ttf",
        bundled_dir / "NotoSans-Regular.ttf",
        bundled_dir / "LiberationSans-Regular.ttf",
        Path(windir) / "Fonts" / "arial.ttf",
        Path(windir) / "Fonts" / "segoeui.ttf",
        Path(windir) / "Fonts" / "tahoma.ttf",
        Path(windir) / "Fonts" / "calibri.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
        Path("/usr/share/fonts/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        Path("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"),
        Path("/usr/share/fonts/noto/NotoSans-Regular.ttf"),
        Path("/usr/share/fonts/truetype/freefont/FreeSans.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
        Path("/System/Library/Fonts/Supplemental/Tahoma.ttf"),
        Path("/Library/Fonts/Arial.ttf"),
    ]
    if localappdata:
        candidates.append(Path(localappdata) / "Microsoft" / "Windows" / "Fonts" / "DejaVuSans.ttf")
    return candidates


def _register_unicode_font() -> tuple[str, bool]:
    """
    Đăng ký font TrueType Unicode (hỗ trợ đầy đủ tiếng Việt) cho ReportLab.
    Trả về `(font_name, is_unicode_ttf)`:
    - Nếu người dùng đặt `REPORT_UNICODE_FONT_PATH`, bắt buộc nạp từ đường dẫn đó (ném `RuntimeError` nếu lỗi).
    - Nếu tìm thấy font TrueType hệ thống/bundled, đăng ký `ReportFont` và trả về `("ReportFont", True)`.
    - Nếu không tìm thấy bất kỳ font TrueType nào, trả về `("Helvetica", False)` để báo cáo chuyển sang
      chế độ chuẩn hóa ASCII an toàn (không tuyên bố hỗ trợ Unicode khi dùng Helvetica).
    """
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    configured_path = (
        os.environ.get("REPORT_UNICODE_FONT_PATH", "").strip()
        or getattr(Config, "REPORT_UNICODE_FONT_PATH", "").strip()
    )
    if configured_path:
        custom = Path(configured_path)
        if not custom.is_file():
            raise RuntimeError(
                f"Không tìm thấy tệp font Unicode được cấu hình tại REPORT_UNICODE_FONT_PATH={configured_path!r}."
            )
        try:
            pdfmetrics.registerFont(TTFont("ReportFont", str(custom)))
            return "ReportFont", True
        except Exception as exc:
            raise RuntimeError(
                f"Không thể nạp tệp font Unicode tại REPORT_UNICODE_FONT_PATH={configured_path!r}: {exc}"
            ) from exc

    for path in _get_unicode_font_candidates():
        if path.exists():
<<<<<<< Updated upstream
            pdfmetrics.registerFont(TTFont("ReportFont", str(path)))
            return "ReportFont"
    return "Helvetica"
=======
            try:
                pdfmetrics.registerFont(TTFont("ReportFont", str(path)))
                return "ReportFont", True
            except Exception:  # noqa: BLE001
                continue

    logger.warning(
        "Không tìm thấy font TrueType Unicode trên hệ thống; PDF chuyển sang chế độ Helvetica ASCII fallback. "
        "Đặt biến môi trường REPORT_UNICODE_FONT_PATH trỏ tới tệp .ttf để hiển thị tiếng Việt có dấu."
    )
    return "Helvetica", False
>>>>>>> Stashed changes


def write_pdf(report: dict[str, Any], path: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("Xuất PDF cần thư viện 'reportlab' (pip install reportlab).") from exc

<<<<<<< Updated upstream
    from xml.sax.saxutils import escape

    font = _register_unicode_font()
=======
    font, is_unicode_ttf = _register_unicode_font()
    ascii_fallback = not is_unicode_ttf

>>>>>>> Stashed changes
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9, leading=12)
    title = ParagraphStyle("title", parent=styles["Title"], fontName=font)
    heading = ParagraphStyle("heading", parent=styles["Heading2"], fontName=font)

    def clean_xml(text: Any) -> str:
        return _sanitize_xml_text(text, ascii_fallback=ascii_fallback)

    def para(text: Any) -> Paragraph:
<<<<<<< Updated upstream
        return Paragraph(escape("" if text is None else str(text)), body)

    story: list[Any] = [Paragraph("OWASP Automated Pentest Report", title), Spacer(1, 0.4 * cm)]
    story.append(Paragraph("Thông tin phiên kiểm thử", heading))
=======
        return Paragraph(clean_xml(text), body)

    sev_colors = {
        "CRITICAL": "#8e0000",
        "HIGH": "#d9534f",
        "MEDIUM": "#f0ad4e",
        "LOW": "#5bc0de",
        "INFO": "#999999",
    }

    story: list[Any] = [
        Paragraph(clean_xml("OWASP Automated Pentest Report"), title),
        Paragraph(clean_xml("Báo cáo Kiểm thử Thâm nhập Web Tự động theo chuẩn OWASP"), subtitle),
        Spacer(1, 0.4 * cm),
    ]

    if ascii_fallback:
        story.append(
            para(
                "[Note: No Unicode TrueType font found; text transliterated to ASCII. "
                "Set REPORT_UNICODE_FONT_PATH to a .ttf font file for full Vietnamese diacritics.]"
            )
        )
        story.append(Spacer(1, 0.2 * cm))

    # 1. Thông tin phiên kiểm thử
    story.append(Paragraph(clean_xml("1. Thông tin phiên kiểm thử (Scan Session & Scope)"), heading))
>>>>>>> Stashed changes
    for line in _summary_lines(report):
        story.append(para(line))
    story.append(Spacer(1, 0.4 * cm))

<<<<<<< Updated upstream
    sev_colors = {
        "CRITICAL": "#8e0000", "HIGH": "#d9534f", "MEDIUM": "#f0ad4e", "LOW": "#5bc0de", "INFO": "#999999",
    }
    findings = report.get("findings", [])
    story.append(Paragraph("Chi tiết lỗ hổng", heading))
=======
    # 2. Executive Summary & biểu đồ phân bố mức độ nghiêm trọng (luôn tính từ findings thực tế)
    summary = _compute_normalized_summary(report)
    counts = summary["severity_counts"]
    findings = report.get("findings", [])
    total_findings = summary["total_findings"]

    story.append(Paragraph(clean_xml("2. Tóm lược điều hành (Executive Summary)"), heading))
    story.append(
        para(
            f"Tổng số điểm cuối (endpoints) đã rà quét: {summary.get('total_endpoints', 0)} | "
            f"Tổng số phát hiện lỗ hổng: {total_findings}."
        )
    )
    story.append(Spacer(1, 0.2 * cm))

    dist_rows: list[list[Any]] = [[para("Mức độ (Severity)"), para("Số lượng"), para("Tỷ lệ / Phân bố")]]
    for sev in SEVERITY_ORDER:
        cnt = int(counts.get(sev, 0) or 0)
        ratio = (cnt / total_findings * 100.0) if total_findings > 0 else 0.0
        bar_blocks = int(round(ratio / 5.0)) if cnt > 0 else 0
        bar_text = ("#" * max(bar_blocks, 1 if cnt > 0 else 0)) + f" {ratio:.1f}%"
        dist_rows.append([para(sev), para(str(cnt)), para(bar_text)])

    dist_table = Table(dist_rows, colWidths=[4 * cm, 3 * cm, 9.5 * cm])
    dist_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(dist_table)
    story.append(Spacer(1, 0.4 * cm))

    # 3. Chi tiết kỹ thuật từng phát hiện
    story.append(Paragraph(clean_xml("3. Chi tiết kỹ thuật các phát hiện (Technical Findings)"), heading))
>>>>>>> Stashed changes
    if not findings:
        story.append(para("Không phát hiện lỗ hổng nào."))
    for idx, f in enumerate(findings, 1):
        rows = [
            ["Severity", f["severity"]],
            ["URL", f["target_url"]],
            ["Parameter", f.get("parameter") or "-"],
            ["Payload", f.get("payload") or "-"],
            ["CWE / OWASP", f"{f.get('cwe_id') or '-'} / {f.get('owasp_category') or '-'}"],
            ["Evidence", f.get("evidence") or "-"],
            ["Remediation", f.get("remediation") or "-"],
        ]
        table = Table(
            [[para(k), para(v)] for k, v in rows],
            colWidths=[3 * cm, 13.5 * cm],
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(sev_colors.get(f["severity"], "#999999"))),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
<<<<<<< Updated upstream
        story += [Paragraph(f"{idx}. {escape(f['vuln_name'])}", ParagraphStyle("h3", parent=heading, fontSize=11)), table, Spacer(1, 0.3 * cm)]

    SimpleDocTemplate(str(path), pagesize=A4, title="OWASP Pentest Report").build(story)
=======
        story += [
            Paragraph(
                f"{idx}. {clean_xml(vuln_name)}",
                ParagraphStyle("h3", parent=heading, fontSize=11),
            ),
            table,
            Spacer(1, 0.3 * cm),
        ]

    target_dest: str | IO[bytes] = str(destination) if isinstance(destination, (Path, str)) else destination
    SimpleDocTemplate(
        target_dest,
        pagesize=A4,
        title="OWASP Pentest Report",
        pageCompression=0,
    ).build(story)


def render_pdf_bytes(report: dict[str, Any]) -> bytes:
    """Kết xuất báo cáo PDF trực tiếp ra bộ nhớ đệm bytes (không ghi đường dẫn từ client)."""
    buffer = io.BytesIO()
    write_pdf(report, buffer)
    return buffer.getvalue()
>>>>>>> Stashed changes


def export_report(report: dict[str, Any], output_path: str | Path, fmt: str | None = None) -> Path:
    """
    Ghi báo cáo ra tệp. Định dạng suy ra từ đuôi tệp nếu `fmt` không được truyền.
    Hỗ trợ: txt, json, pdf.
    """
    path = Path(output_path)
    fmt = (fmt or path.suffix.lstrip(".") or "txt").lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Định dạng '{fmt}' không được hỗ trợ. Chọn: {', '.join(SUPPORTED_FORMATS)}")
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    elif fmt == "txt":
        path.write_text(render_text(report), encoding="utf-8")
    else:
        write_pdf(report, path)
    return path
