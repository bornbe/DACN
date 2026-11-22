"""
Dịch vụ xuất báo cáo quét (TXT / JSON / PDF) và dựng bảng kết quả dạng Markdown.
Dùng chung cho CLI (Issue #4.2) và API tải báo cáo kỹ thuật (Issue #6.2).
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from config.config import BASE_DIR, Config

if TYPE_CHECKING:
    from models.scan_job import CrawledEndpoint, ScanSession
    from models.vulnerability import VulnerabilityFinding

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SUPPORTED_FORMATS = ("txt", "json", "pdf", "docx")
API_REPORT_FORMATS = ("txt", "pdf", "docx")

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


def _cell(value: Any, limit: int = 80) -> str:
    """Làm sạch giá trị để đặt vào ô bảng Markdown."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS_RE.sub("", text)
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


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


def render_markdown_table(findings: list[dict[str, Any]]) -> str:
    """Bảng Markdown tóm tắt các lỗ hổng."""
    if not findings:
        return "_Không phát hiện lỗ hổng nào._"
    lines = [
        "| # | Severity | Vulnerability | URL | Parameter | CWE |",
        "|---|----------|---------------|-----|-----------|-----|",
    ]
    for idx, f in enumerate(findings, 1):
        vuln_name = f.get("vuln_name") or f.get("vuln_type") or "-"
        param = f.get("parameter") if f.get("parameter") is not None else f.get("param")
        lines.append(
            f"| {idx} | {_cell(f.get('severity'))} | {_cell(vuln_name, 60)} | "
            f"{_cell(f.get('target_url'), 60)} | {_cell(param, 30)} | {_cell(f.get('cwe_id'), 12)} |"
        )
    return "\n".join(lines)


def _summary_lines(report: dict[str, Any]) -> list[str]:
    summary = _compute_normalized_summary(report)
    counts = summary["severity_counts"]
    lines: list[str] = []
    if report.get("session_id") is not None:
        lines.append(f"Session ID    : #{report.get('session_id')}")
    lines.append(f"Target        : {report.get('target_url')}")
    if report.get("max_depth") is not None:
        lines.append(f"Scope Depth   : max_depth={report.get('max_depth')}")
    lines += [
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
        vuln_name = f.get("vuln_name") or f.get("vuln_type") or "Unknown Vulnerability"
        param = f.get("parameter") if f.get("parameter") is not None else f.get("param")
        out += [
            f"[{idx}] [{f.get('severity', 'INFO')}] {vuln_name}",
            f"    URL         : {f.get('target_url') or '-'}",
            f"    Parameter   : {param or '-'}",
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


def write_pdf(report: dict[str, Any], destination: Path | str | IO[bytes]) -> None:
    """
    Kết xuất báo cáo PDF chuyên nghiệp gồm:
    1. Bìa / Thông tin phiên kiểm thử (Target, Scope, Thời gian, Trạng thái).
    2. Tóm lược điều hành (Executive Summary) kèm bảng & thanh biểu đồ phân bố mức độ nghiêm trọng.
    3. Bảng chi tiết kỹ thuật cho từng phát hiện (CWE/OWASP, Payload, Evidence, Remediation).
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("Xuất PDF cần thư viện 'reportlab' (pip install reportlab).") from exc

    font, is_unicode_ttf = _register_unicode_font()
    ascii_fallback = not is_unicode_ttf

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9, leading=12)
    title = ParagraphStyle("title", parent=styles["Title"], fontName=font, fontSize=18, leading=22)
    subtitle = ParagraphStyle(
        "subtitle",
        parent=styles["Normal"],
        fontName=font,
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
    )
    heading = ParagraphStyle("heading", parent=styles["Heading2"], fontName=font, fontSize=13, leading=16)

    def clean_xml(text: Any) -> str:
        return _sanitize_xml_text(text, ascii_fallback=ascii_fallback)

    def para(text: Any) -> Paragraph:
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
    for line in _summary_lines(report):
        story.append(para(line))
    story.append(Spacer(1, 0.4 * cm))

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
    if not findings:
        story.append(para("Không phát hiện lỗ hổng nào trong phạm vi kiểm thử."))
    for idx, f in enumerate(findings, 1):
        vuln_name = f.get("vuln_name") or f.get("vuln_type") or "Unknown Vulnerability"
        sev = (f.get("severity") or "INFO").upper()
        param = f.get("parameter") if f.get("parameter") is not None else f.get("param")
        rows = [
            ["Severity", sev],
            ["URL", f.get("target_url") or "-"],
            ["Parameter", param or "-"],
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
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(sev_colors.get(sev, "#999999"))),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
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


def get_documents_dir() -> Path:
    """Trả về đường dẫn thư mục Documents của người dùng hiện tại."""
    docs = Path.home() / "Documents"
    docs.mkdir(parents=True, exist_ok=True)
    return docs


def resolve_report_output_path(
    output_path: str | Path | None,
    fmt: str = "pdf",
    target_url: str = "",
) -> Path:
    """
    Chuẩn hóa đường dẫn xuất báo cáo:
    - Nếu không truyền `output_path`, tự sinh tên tệp theo domain + thời gian trong `Documents`.
    - Nếu chỉ truyền tên tệp (không kèm thư mục, ví dụ `baocao.pdf` hoặc `baocao.docx`), tự lưu vào `Documents`.
    - Nếu truyền đường dẫn có thư mục cụ thể (ví dụ `benchmark/artifacts/...`), giữ nguyên đường dẫn đó.
    """
    if output_path is None or not str(output_path).strip():
        host = (urlsplit(target_url).hostname or "target").replace(".", "_")
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return get_documents_dir() / f"scan_report_{host}_{stamp}.{fmt.lower()}"

    raw = str(output_path).strip()
    candidate = Path(raw)
    if candidate.parent == Path(".") and not raw.startswith((".", "/", "\\")):
        return get_documents_dir() / candidate.name
    return candidate


def _clean_docx_text(value: Any) -> str:
    text = "" if value is None else str(value)
    return _CONTROL_CHARS_RE.sub("", text)


def write_docx(report: dict[str, Any], destination: str | Path | IO[bytes]) -> None:
    """Xuất báo cáo kỹ thuật định dạng Word (.docx) bằng thư viện python-docx."""
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except ImportError as exc:
        raise RuntimeError(
            "Thiếu thư viện python-docx. Cài đặt bằng: pip install python-docx"
        ) from exc

    doc = Document()
    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Calibri"
    normal_style.font.size = Pt(10.5)

    title = doc.add_heading("BÁO CÁO KIỂM THỬ BẢO MẬT WEB (OWASP)", level=0)
    if title.runs:
        title.runs[0].font.color.rgb = RGBColor(0x1E, 0x3A, 0x8A)

    summary = _compute_normalized_summary(report)
    findings = report.get("findings") or []

    # 1. Thông tin phiên kiểm thử
    doc.add_heading("1. Thông tin phiên kiểm thử", level=1)
    info_items = [
        ("Mục tiêu (Target)", report.get("target_url") or "-"),
        ("Trạng thái", report.get("status") or "-"),
        ("Thời gian", f"{report.get('start_time') or '-'} -> {report.get('end_time') or '-'}"),
        ("Thời lượng", f"{report.get('duration_seconds', 0)}s"),
        ("Modules", ", ".join(report.get("modules") or []) or "-"),
        ("Trang đã crawl", str(summary.get("pages_crawled", 0))),
        ("Tổng endpoints", str(summary.get("total_endpoints", 0))),
        ("Tổng lỗ hổng phát hiện", str(summary.get("total_findings", 0))),
    ]
    info_table = doc.add_table(rows=len(info_items), cols=2)
    info_table.style = "Table Grid"
    for row_idx, (label, val) in enumerate(info_items):
        row_cells = info_table.rows[row_idx].cells
        row_cells[0].text = _clean_docx_text(label)
        if row_cells[0].paragraphs and row_cells[0].paragraphs[0].runs:
            row_cells[0].paragraphs[0].runs[0].bold = True
        row_cells[1].text = _clean_docx_text(val)

    # 2. Tóm lược phân bố lỗ hổng
    doc.add_heading("2. Tóm lược điều hành & Phân bố lỗ hổng", level=1)
    counts = summary.get("severity_counts") or {}
    total_findings = int(summary.get("total_findings") or 0)
    dist_table = doc.add_table(rows=len(SEVERITY_ORDER) + 1, cols=3)
    dist_table.style = "Table Grid"
    for col_idx, header_text in enumerate(("Mức độ", "Số lượng", "Tỉ lệ (%)")):
        cell = dist_table.rows[0].cells[col_idx]
        cell.text = header_text
        if cell.paragraphs and cell.paragraphs[0].runs:
            cell.paragraphs[0].runs[0].bold = True
    for idx, sev in enumerate(SEVERITY_ORDER, 1):
        cnt = int(counts.get(sev, 0) or 0)
        ratio = (cnt / total_findings * 100.0) if total_findings > 0 else 0.0
        dist_table.rows[idx].cells[0].text = sev
        dist_table.rows[idx].cells[1].text = str(cnt)
        dist_table.rows[idx].cells[2].text = f"{ratio:.1f}%"

    # 3. Chi tiết kỹ thuật các phát hiện
    doc.add_heading("3. Chi tiết kỹ thuật các phát hiện (Technical Findings)", level=1)
    if not findings:
        doc.add_paragraph("Không phát hiện lỗ hổng nào trong phạm vi kiểm thử.")
    for idx, f in enumerate(findings, 1):
        vuln_name = f.get("vuln_name") or f.get("vuln_type") or "Unknown Vulnerability"
        sev = (f.get("severity") or "INFO").upper()
        param = f.get("parameter") if f.get("parameter") is not None else f.get("param")
        doc.add_heading(f"{idx}. {_clean_docx_text(vuln_name)}", level=2)

        detail_rows = [
            ("Severity", sev),
            ("URL", f.get("target_url") or "-"),
            ("Parameter", param or "-"),
            ("Payload", f.get("payload") or "-"),
            ("CWE / OWASP", f"{f.get('cwe_id') or '-'} / {f.get('owasp_category') or '-'}"),
            ("Evidence", f.get("evidence") or "-"),
            ("Remediation", f.get("remediation") or "-"),
        ]
        f_table = doc.add_table(rows=len(detail_rows), cols=2)
        f_table.style = "Table Grid"
        for r_idx, (k, v) in enumerate(detail_rows):
            cells = f_table.rows[r_idx].cells
            cells[0].text = k
            if cells[0].paragraphs and cells[0].paragraphs[0].runs:
                cells[0].paragraphs[0].runs[0].bold = True
            cells[1].text = _clean_docx_text(v)
        doc.add_paragraph()

    target_dest: str | IO[bytes] = str(destination) if isinstance(destination, (Path, str)) else destination
    doc.save(target_dest)


def render_docx_bytes(report: dict[str, Any]) -> bytes:
    """Kết xuất báo cáo Word (.docx) trực tiếp ra bộ nhớ đệm bytes."""
    buffer = io.BytesIO()
    write_docx(report, buffer)
    return buffer.getvalue()


def export_report(report: dict[str, Any], output_path: str | Path, fmt: str | None = None) -> Path:
    """
    Ghi báo cáo ra tệp. Định dạng suy ra từ đuôi tệp nếu `fmt` không được truyền.
    Nếu chỉ truyền tên tệp (không có thư mục), tự động lưu vào thư mục `Documents`.
    Hỗ trợ: txt, json, pdf, docx.
    """
    raw_path = Path(output_path)
    resolved_fmt = (fmt or raw_path.suffix.lstrip(".") or "txt").lower()
    if resolved_fmt not in SUPPORTED_FORMATS:
        raise ValueError(f"Định dạng '{resolved_fmt}' không được hỗ trợ. Chọn: {', '.join(SUPPORTED_FORMATS)}")

    path = resolve_report_output_path(output_path, fmt=resolved_fmt, target_url=str(report.get("target_url") or ""))
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    if resolved_fmt == "json":
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    elif resolved_fmt == "txt":
        path.write_text(render_text(report), encoding="utf-8")
    elif resolved_fmt == "docx":
        write_docx(report, path)
    else:
        write_pdf(report, path)
    return path
