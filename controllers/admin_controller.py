"""
HTTP API quản trị hệ thống dành riêng cho Administrator (RBAC & Audit Logs).
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from middleware.auth_middleware import require_role
from services import audit_service, user_service

admin_blueprint = Blueprint("admin", __name__, url_prefix="/api/admin")


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@admin_blueprint.get("/users")
@require_role("admin")
def list_users_route() -> ResponseReturnValue:
    """Liệt kê toàn bộ người dùng trong hệ thống (chỉ Admin)."""
    with _session_factory()() as db:
        users = user_service.list_users(db)
        return jsonify(users=[u.to_dict() for u in users]), 200


@admin_blueprint.patch("/users/<int:target_user_id>")
@require_role("admin")
def update_user_route(target_user_id: int) -> ResponseReturnValue:
    """Cập nhật vai trò (`admin` / `tester` / `pentester`) hoặc khóa/mở khóa tài khoản."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Bad Request", message="Body JSON không hợp lệ."), 400

    with _session_factory()() as db:
        try:
            updated = user_service.update_user_admin(
                db,
                target_user_id=target_user_id,
                actor_user_id=g.user.id,
                role=payload.get("role"),
                is_active=payload.get("is_active"),
            )
        except LookupError as exc:
            return jsonify(error="Not Found", message=str(exc)), 404
        except ValueError as exc:
            return jsonify(error="Bad Request", message=str(exc)), 400

        audit_service.record_audit_log(
            db,
            action="ADMIN_USER_UPDATE",
            user_id=g.user.id,
            resource_type="user",
            resource_id=updated.id,
            metadata={"role": updated.role, "is_active": updated.is_active},
        )
        return jsonify(user=updated.to_dict()), 200


@admin_blueprint.get("/audit-logs")
@require_role("admin")
def list_audit_logs_route() -> ResponseReturnValue:
    """Truy vấn nhật ký kiểm toán hệ thống, hỗ trợ lọc `action`, `user_id`, `limit`."""
    action = request.args.get("action")
    raw_user_id = request.args.get("user_id")
    raw_limit = request.args.get("limit", "100")

    user_id: int | None = None
    if raw_user_id:
        try:
            user_id = int(raw_user_id)
        except ValueError:
            return jsonify(error="Bad Request", message="Tham số user_id không hợp lệ."), 400

    try:
        limit = int(raw_limit)
    except ValueError:
        return jsonify(error="Bad Request", message="Tham số limit không hợp lệ."), 400

    with _session_factory()() as db:
        logs = audit_service.list_audit_logs(db, action=action, user_id=user_id, limit=limit)
        return jsonify(audit_logs=[entry.to_dict() for entry in logs]), 200
