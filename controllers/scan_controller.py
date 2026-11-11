"""
HTTP API quản lý scan và findings - Issue #5.1/#5.2.
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from middleware.auth_middleware import require_auth
from schemas.requested_scope_schema import validate_scan_request
from schemas.vulnerability_schema import format_vulnerability
from services import scan_service
from tasks import scan_tasks

scan_blueprint = Blueprint("scans", __name__, url_prefix="/api")


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@scan_blueprint.post("/scans")
@require_auth
def create_scan_route() -> ResponseReturnValue:
    """Tạo phiên PENDING, enqueue nền và trả HTTP 202."""
    try:
        values = validate_scan_request(request.get_json(silent=True))
    except ValueError as exc:
        return jsonify(error="Bad Request", message=str(exc)), 400

    with _session_factory()() as db:
        scan = scan_service.create_scan(
            db,
            user_id=g.user.id,
            url=values["url"],
            max_depth=values["max_depth"],
            modules=values["modules"],
        )
        session_id = scan.id
        status = scan.status
    try:
        scan_tasks.submit(session_id)
    except Exception as exc:
        scan_service.mark_scan_failed(session_id, str(exc))
        current_app.logger.exception("Không thể enqueue scan job %s", session_id)
        return jsonify(error="Service Unavailable", message="Không thể đưa tác vụ vào hàng đợi."), 503
    return jsonify(session_id=session_id, status=status), 202


@scan_blueprint.get("/scans/<int:session_id>")
@require_auth
def get_scan_route(session_id: int) -> ResponseReturnValue:
    """Trả trạng thái scan chỉ cho người sở hữu."""
    with _session_factory()() as db:
        scan = scan_service.get_scan(db, session_id, g.user.id)
        if scan is None:
            return jsonify(error="Not Found", message="Không tìm thấy phiên quét."), 404
        return jsonify(scan=scan.to_dict()), 200


@scan_blueprint.get("/scans/<int:session_id>/findings")
@require_auth
def get_findings_route(session_id: int) -> ResponseReturnValue:
    """Trả findings của phiên quét chỉ cho người sở hữu."""
    with _session_factory()() as db:
        scan = scan_service.get_scan(db, session_id, g.user.id)
        if scan is None:
            return jsonify(error="Not Found", message="Không tìm thấy phiên quét."), 404
        findings = scan_service.list_findings(db, session_id, g.user.id)
        return jsonify(findings=[format_vulnerability(item) for item in findings]), 200


@scan_blueprint.post("/scans/<int:session_id>/stop")
@require_auth
def stop_scan_route(session_id: int) -> ResponseReturnValue:
    """Yêu cầu dừng một phiên quét; chỉ chủ sở hữu mới được dừng (fix review Critical #2)."""
    with _session_factory()() as db:
        result = scan_service.stop_scan(db, session_id, g.user.id)
    if result is None:
        return jsonify(error="Not Found", message="Không tìm thấy phiên quét."), 404
    if result["state"] == "already_finished":
        return jsonify(
            error="Conflict",
            message="Phiên quét đã kết thúc, không thể dừng.",
            status=result["status"],
        ), 409
    return jsonify(session_id=session_id, state=result["state"], status=result["status"]), 202


@scan_blueprint.get("/scans")
@require_auth
def list_scans_route() -> ResponseReturnValue:
    """Liệt kê các phiên quét của người dùng hiện tại."""
    with _session_factory()() as db:
        scans = scan_service.list_scans(db, g.user.id)
        return jsonify(scans=[scan.to_dict() for scan in scans]), 200