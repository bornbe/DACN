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
from services import audit_service, scan_service, target_service
from tasks import scan_tasks

scan_blueprint = Blueprint("scans", __name__, url_prefix="/api")


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@scan_blueprint.post("/scans")
@require_auth
def create_scan_route() -> ResponseReturnValue:
    """Tạo phiên PENDING, enqueue nền và trả HTTP 202."""
    raw_body = request.get_json(silent=True)
    try:
        values = validate_scan_request(raw_body)
    except ValueError as exc:
        return jsonify(error="Bad Request", message=str(exc)), 400

    raw_target_id = raw_body.get("target_id") if isinstance(raw_body, dict) else None
    target_id: int | None = None
    if raw_target_id is not None:
        if isinstance(raw_target_id, bool) or not isinstance(raw_target_id, int):
            return jsonify(error="Bad Request", message="target_id phải là số nguyên."), 400
        target_id = raw_target_id

    with _session_factory()() as db:
        matched_target = target_service.find_authorized_target_for_scan(
            db,
            url=values["url"],
            user_id=g.user.id,
            is_admin=g.user.is_admin,
            target_id=target_id,
        )
        if current_app.config.get("TARGET_VERIFICATION_REQUIRED") and not g.user.is_admin:
            if matched_target is None:
                return (
                    jsonify(
                        error="Forbidden",
                        message="Mục tiêu chưa được xác minh quyền sở hữu hoặc chưa được Admin phê duyệt.",
                    ),
                    403,
                )

        scan = scan_service.create_scan(
            db,
            user_id=g.user.id,
            url=values["url"],
            max_depth=values["max_depth"],
            modules=values["modules"],
            target_id=matched_target.id if matched_target is not None else None,
        )
        session_id = scan.id
        status = scan.status
        audit_service.record_audit_log(
            db,
            action="SCAN_START",
            user_id=g.user.id,
            resource_type="scan",
            resource_id=session_id,
            metadata={
                "url": values["url"],
                "modules": values["modules"],
                "max_depth": values["max_depth"],
            },
        )
    try:
        scan_tasks.submit(session_id)
    except Exception as exc:
        scan_service.mark_scan_failed(session_id, str(exc))
        current_app.logger.exception("Không thể enqueue scan job %s", session_id)
        return jsonify(error="Service Unavailable", message="Không thể đưa tác vụ vào hàng đợi."), 503
    return jsonify(session_id=session_id, status=status), 202


@scan_blueprint.get("/scans/compare")
@require_auth
def compare_scans_route() -> ResponseReturnValue:
    """So sánh kết quả lỗ hổng giữa hai phiên quét (`?base=<id>&target=<id>`)."""
    raw_base = request.args.get("base", "").strip()
    raw_target = request.args.get("target", "").strip()
    if not raw_base or not raw_target:
        return (
            jsonify(
                error="Bad Request",
                message="Cần truyền đầy đủ tham số query base và target.",
            ),
            400,
        )
    try:
        base_id = int(raw_base)
        target_id = int(raw_target)
    except ValueError:
        return jsonify(error="Bad Request", message="Tham số base và target phải là số nguyên."), 400

    with _session_factory()() as db:
        diff = scan_service.compare_scans(
            db,
            base_session_id=base_id,
            target_session_id=target_id,
            user_id=g.user.id,
            is_admin=g.user.is_admin,
        )
        if diff is None:
            return jsonify(error="Not Found", message="Không tìm thấy một hoặc cả hai phiên quét."), 404
        return jsonify(comparison=diff), 200


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
        if result is not None and result["state"] != "already_finished":
            audit_service.record_audit_log(
                db,
                action="SCAN_STOP",
                user_id=g.user.id,
                resource_type="scan",
                resource_id=session_id,
                metadata={"state": result["state"], "status": result["status"]},
            )
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