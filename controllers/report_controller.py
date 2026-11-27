"""
Controller phục vụ giao diện Web Dashboard (Issue #6.1) và API tải báo cáo kỹ thuật TXT/PDF (Issue #6.2).
"""

from __future__ import annotations

from flask import Blueprint, Response, current_app, g, jsonify, render_template, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from middleware.auth_middleware import require_auth
from models.report import Report
from services import audit_service, report_service, scan_service

report_blueprint = Blueprint("reports", __name__)


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@report_blueprint.get("/")
@report_blueprint.get("/dashboard")
def dashboard_page() -> ResponseReturnValue:
    """Trang tổng quan Dashboard (Issue #6.1)."""
    return render_template("dashboard.html")


@report_blueprint.get("/scans/<int:session_id>")
def scan_detail_page(session_id: int) -> ResponseReturnValue:
    """Trang chi tiết phiên quét và theo dõi tiến độ thời gian thực (Issue #6.1)."""
    return render_template("scan_detail.html", session_id=session_id)


@report_blueprint.get("/api/scans/<int:session_id>/report")
@require_auth
def download_scan_report(session_id: int) -> ResponseReturnValue:
    """
    API tải báo cáo kỹ thuật của một phiên quét (Issue #6.2):
    GET /api/scans/<id>/report?format=pdf|txt
    - Yêu cầu xác thực JWT.
    - Chỉ chủ sở hữu phiên quét mới được tải báo cáo; trả 404 nếu không tồn tại hoặc khác chủ sở hữu.
    - Chỉ chấp nhận chính xác format 'pdf' hoặc 'txt'; trả 400 nếu thiếu hoặc sai định dạng.
    """
    fmt = (request.args.get("format") or "").strip().lower()
    if fmt not in report_service.API_REPORT_FORMATS:
        return (
            jsonify(
                error="Bad Request",
                message="Tham số format không hợp lệ; chỉ hỗ trợ 'pdf', 'html', 'json', 'docx' hoặc 'txt'.",
            ),
            400,
        )

    owner_filter = None if g.user.is_admin else g.user.id
    with _session_factory()() as db:
        scan = scan_service.get_scan(db, session_id, owner_filter)
        if scan is None:
            return jsonify(error="Not Found", message="Không tìm thấy phiên quét."), 404
        findings = scan_service.list_findings(db, session_id, owner_filter)
        endpoints = list(scan.endpoints or [])
        report_data = report_service.build_session_report(scan, findings=findings, endpoints=endpoints)

        report_record = Report(
            session_id=session_id,
            user_id=g.user.id,
            report_format=fmt,
            file_path=f"scan-report-{session_id}.{fmt}",
        )
        db.add(report_record)
        audit_service.record_audit_log(
            db,
            action="REPORT_EXPORT",
            user_id=g.user.id,
            resource_type="scan",
            resource_id=session_id,
            metadata={"format": fmt},
            commit=True,
        )

    headers = {
        "Content-Disposition": f'attachment; filename="scan-report-{session_id}.{fmt}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }

    if fmt == "txt":
        content = report_service.render_text(report_data)
        return Response(content, status=200, mimetype="text/plain; charset=utf-8", headers=headers)

    if fmt == "json":
        json_bytes = report_service.render_json_bytes(report_data)
        return Response(json_bytes, status=200, mimetype="application/json; charset=utf-8", headers=headers)

    if fmt == "html":
        # Gắn CSP chặt chẽ cho file HTML tải về để chặn thực thi mọi script nội tuyến
        html_headers = dict(headers)
        html_headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
        html_bytes = report_service.render_html_bytes(report_data)
        return Response(html_bytes, status=200, mimetype="text/html; charset=utf-8", headers=html_headers)

    if fmt == "docx":
        try:
            docx_bytes = report_service.render_docx_bytes(report_data)
        except RuntimeError as exc:
            return jsonify(error="Service Unavailable", message=str(exc)), 503
        return Response(
            docx_bytes,
            status=200,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers=headers,
        )

    try:
        pdf_bytes = report_service.render_pdf_bytes(report_data)
    except RuntimeError as exc:
        return jsonify(error="Service Unavailable", message=str(exc)), 503

    return Response(pdf_bytes, status=200, mimetype="application/pdf", headers=headers)
