"""
Dịch vụ xuất báo cáo quét (TXT / JSON / PDF) và dựng bảng kết quả dạng Markdown.
Dùng chung cho CLI (Issue #4.2) và API tải báo cáo kỹ thuật (Issue #6.2).
"""

from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any
from xml.sax.saxutils import escape

if TYPE_CHECKING:
    from models.scan_job import CrawledEndpoint, ScanSession
    from models.vulnerability import VulnerabilityFinding

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SUPPORTED_FORMATS = ("txt", "json", "pdf")
API_REPORT_FORMATS = ("txt", "pdf")

# Loại bỏ các ký tự điều khiển XML không hợp lệ trước khi đưa vào ReportLab Paragraph
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_xml_text(value: Any) -> str:
    text = "" if value is None else str(value)
    cleaned = _CONTROL_CHARS_RE.sub("", text)
    return escape(cleaned)


def _cell(value: Any, limit: int = 80) -> str:
    """Làm sạch giá trị để đặt vào ô bảng Markdown."""
    text = "" if value is None else str(value)
    text = _CONTROL_CHARS_RE.sub("", text)
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


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
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
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
            try:
                pdfmetrics.registerFont(TTFont("ReportFont", str(path)))
                return "ReportFont"
            except Exception:  # noqa: BLE001
                continue
    return "Helvetica"


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

    font = _register_unicode_font()
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

    def para(text: Any) -> Paragraph:
        return Paragraph(_sanitize_xml_text(text), body)

    sev_colors = {
        "CRITICAL": "#8e0000",
        "HIGH": "#d9534f",
        "MEDIUM": "#f0ad4e",
        "LOW": "#5bc0de",
        "INFO": "#999999",
    }

    story: list[Any] = [
        Paragraph("OWASP Automated Pentest Report", title),
        Paragraph("Báo cáo Kiểm thử Thâm nhập Web Tự động theo chuẩn OWASP", subtitle),
        Spacer(1, 0.4 * cm),
    ]

    # 1. Thông tin phiên kiểm thử
    story.append(Paragraph("1. Thông tin phiên kiểm thử (Scan Session & Scope)", heading))
    for line in _summary_lines(report):
        story.append(para(line))
    story.append(Spacer(1, 0.4 * cm))

    # 2. Executive Summary & biểu đồ phân bố mức độ nghiêm trọng
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
    findings = report.get("findings", [])
    total_findings = max(int(summary.get("total_findings", len(findings)) or 0), len(findings))

    story.append(Paragraph("2. Tóm lược điều hành (Executive Summary)", heading))
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
    story.append(Paragraph("3. Chi tiết kỹ thuật các phát hiện (Technical Findings)", heading))
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
                f"{idx}. {_sanitize_xml_text(vuln_name)}",
                ParagraphStyle("h3", parent=heading, fontSize=11),
            ),
            table,
            Spacer(1, 0.3 * cm),
        ]

    target_dest: str | IO[bytes] = str(destination) if isinstance(destination, (Path, str)) else destination
    SimpleDocTemplate(target_dest, pagesize=A4, title="OWASP Pentest Report").build(story)


def render_pdf_bytes(report: dict[str, Any]) -> bytes:
    """Kết xuất báo cáo PDF trực tiếp ra bộ nhớ đệm bytes (không ghi đường dẫn từ client)."""
    buffer = io.BytesIO()
    write_pdf(report, buffer)
    return buffer.getvalue()


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
