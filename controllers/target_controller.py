"""
HTTP API quản lý mục tiêu kiểm thử (Target Management) và xác minh quyền sở hữu.
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from middleware.auth_middleware import require_auth, require_role
from services import audit_service, target_service

target_blueprint = Blueprint("targets", __name__, url_prefix="/api")


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@target_blueprint.get("/targets")
@require_auth
def list_targets_route() -> ResponseReturnValue:
    """Liệt kê danh sách mục tiêu của người dùng (hoặc tất cả nếu là Admin)."""
    with _session_factory()() as db:
        items = target_service.list_targets(db, user_id=g.user.id, is_admin=g.user.is_admin)
        return jsonify(targets=[t.to_dict(include_token=True) for t in items]), 200


@target_blueprint.post("/targets")
@require_auth
def create_target_route() -> ResponseReturnValue:
    """Khai báo mục tiêu mới và sinh mã xác minh quyền sở hữu."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Bad Request", message="Body JSON không hợp lệ."), 400

    raw_url = payload.get("url")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify(error="Bad Request", message="Trường url là bắt buộc."), 400

    with _session_factory()() as db:
        try:
            target = target_service.create_target(
                db,
                owner_id=g.user.id,
                url=raw_url,
                name=payload.get("name"),
                description=payload.get("description"),
                scope=payload.get("scope"),
            )
        except ValueError as exc:
            return jsonify(error="Bad Request", message=str(exc)), 400

        audit_service.record_audit_log(
            db,
            action="TARGET_CREATE",
            user_id=g.user.id,
            resource_type="target",
            resource_id=target.id,
            metadata={"url": target.url, "name": target.name},
        )
        return jsonify(target=target.to_dict(include_token=True)), 201


@target_blueprint.post("/targets/<int:target_id>/verify")
@require_auth
def verify_target_route(target_id: int) -> ResponseReturnValue:
    """Xác minh quyền sở hữu mục tiêu qua `.well-known/pentest-verify.txt` hoặc `DNS_TXT`."""
    payload = request.get_json(silent=True) or {}
    method = payload.get("method", "WELL_KNOWN") if isinstance(payload, dict) else "WELL_KNOWN"

    with _session_factory()() as db:
        try:
            target = target_service.verify_target_ownership(
                db,
                target_id,
                user_id=g.user.id,
                is_admin=g.user.is_admin,
                method=str(method),
            )
        except LookupError as exc:
            return jsonify(error="Not Found", message=str(exc)), 404
        except ValueError as exc:
            return jsonify(error="Bad Request", message=str(exc)), 400
        except (PermissionError, RuntimeError) as exc:
            return jsonify(error="Unprocessable Entity", message=str(exc)), 422

        audit_service.record_audit_log(
            db,
            action="TARGET_VERIFY",
            user_id=g.user.id,
            resource_type="target",
            resource_id=target.id,
            metadata={"method": target.verification_method, "status": target.authorization_status},
        )
        return jsonify(target=target.to_dict(include_token=True)), 200


@target_blueprint.post("/targets/<int:target_id>/approve")
@require_role("admin")
def approve_target_route(target_id: int) -> ResponseReturnValue:
    """Quản trị viên phê duyệt quyền kiểm thử mục tiêu."""
    with _session_factory()() as db:
        try:
            target = target_service.set_target_approval(db, target_id, approved=True)
        except LookupError as exc:
            return jsonify(error="Not Found", message=str(exc)), 404
        except ValueError as exc:
            return jsonify(error="Bad Request", message=str(exc)), 400

        audit_service.record_audit_log(
            db,
            action="TARGET_APPROVE",
            user_id=g.user.id,
            resource_type="target",
            resource_id=target.id,
            metadata={"status": target.authorization_status},
        )
        return jsonify(target=target.to_dict(include_token=True)), 200


@target_blueprint.post("/targets/<int:target_id>/reject")
@require_role("admin")
def reject_target_route(target_id: int) -> ResponseReturnValue:
    """Quản trị viên từ chối quyền kiểm thử mục tiêu."""
    with _session_factory()() as db:
        try:
            target = target_service.set_target_approval(db, target_id, approved=False)
        except LookupError as exc:
            return jsonify(error="Not Found", message=str(exc)), 404
        except ValueError as exc:
            return jsonify(error="Bad Request", message=str(exc)), 400

        audit_service.record_audit_log(
            db,
            action="TARGET_REJECT",
            user_id=g.user.id,
            resource_type="target",
            resource_id=target.id,
            metadata={"status": target.authorization_status},
        )
        return jsonify(target=target.to_dict(include_token=True)), 200
