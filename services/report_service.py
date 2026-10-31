"""
Dịch vụ xuất báo cáo quét (TXT / JSON / PDF) và dựng bảng kết quả dạng Markdown.
Dùng chung cho CLI (Issue #4.2); có thể mở rộng cho API tải báo cáo (Issue #6.2).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SUPPORTED_FORMATS = ("txt", "json", "pdf")


def _cell(value: Any, limit: int = 80) -> str:
    """Làm sạch giá trị để đặt vào ô bảng Markdown."""
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


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
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
    lines = [
        f"Target        : {report.get('target_url')}",
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


def _register_unicode_font() -> str:
    """Đăng ký font Unicode (hỗ trợ tiếng Việt) cho PDF; fallback Helvetica."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        Path(windir) / "Fonts" / "arial.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
    ]
    for path in candidates:
        if path.exists():
            pdfmetrics.registerFont(TTFont("ReportFont", str(path)))
            return "ReportFont"
    return "Helvetica"


def write_pdf(report: dict[str, Any], path: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("Xuất PDF cần thư viện 'reportlab' (pip install reportlab).") from exc

    from xml.sax.saxutils import escape

    font = _register_unicode_font()
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["Normal"], fontName=font, fontSize=9, leading=12)
    title = ParagraphStyle("title", parent=styles["Title"], fontName=font)
    heading = ParagraphStyle("heading", parent=styles["Heading2"], fontName=font)

    def para(text: Any) -> Paragraph:
        return Paragraph(escape("" if text is None else str(text)), body)

    story: list[Any] = [Paragraph("OWASP Automated Pentest Report", title), Spacer(1, 0.4 * cm)]
    story.append(Paragraph("Thông tin phiên kiểm thử", heading))
    for line in _summary_lines(report):
        story.append(para(line))
    story.append(Spacer(1, 0.4 * cm))

    sev_colors = {
        "CRITICAL": "#8e0000", "HIGH": "#d9534f", "MEDIUM": "#f0ad4e", "LOW": "#5bc0de", "INFO": "#999999",
    }
    findings = report.get("findings", [])
    story.append(Paragraph("Chi tiết lỗ hổng", heading))
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
        story += [Paragraph(f"{idx}. {escape(f['vuln_name'])}", ParagraphStyle("h3", parent=heading, fontSize=11)), table, Spacer(1, 0.3 * cm)]

    SimpleDocTemplate(str(path), pagesize=A4, title="OWASP Pentest Report").build(story)


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
