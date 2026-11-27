"""
Dịch vụ ghi nhận và truy vấn nhật ký kiểm toán hệ thống (Audit Logging).
Tự động lọc bỏ các khóa nhạy cảm và trích xuất IP người dùng an toàn qua `resolve_client_ip`.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import has_request_context
from sqlalchemy.orm import Session

from middleware.rate_limiter import resolve_client_ip
from models.audit_log import AuditLog
from services.scan_service import _db_lock

logger = logging.getLogger(__name__)

_SENSITIVE_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "secret_key",
        "jwt_secret_key",
        "authorization",
        "verification_token",
    }
)


def _sanitize_metadata(raw: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, Any] = {}
    for key, value in raw.items():
        key_str = str(key)
        if key_str.lower() in _SENSITIVE_METADATA_KEYS:
            continue
        if isinstance(value, dict):
            cleaned[key_str] = _sanitize_metadata(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            cleaned[key_str] = value
        elif isinstance(value, (list, tuple)):
            cleaned[key_str] = [
                item if isinstance(item, (str, int, float, bool)) or item is None else str(item)
                for item in value[:50]
            ]
        else:
            cleaned[key_str] = str(value)[:200]
    return cleaned


def record_audit_log(
    db: Session,
    *,
    action: str,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    ip_address: str | None = None,
    metadata: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog | None:
    """
    Ghi nhận một bản ghi AuditLog an toàn. Nếu gặp lỗi ngoài dự kiến thì ghi warning log
    nhưng không làm sập luồng nghiệp vụ chính.
    """
    try:
        resolved_ip = ip_address
        if not resolved_ip and has_request_context():
            resolved_ip = resolve_client_ip()

        entry = AuditLog(
            user_id=user_id,
            action=action.strip().upper()[:64],
            resource_type=resource_type.strip()[:64] if resource_type else None,
            resource_id=str(resource_id)[:64] if resource_id is not None else None,
            ip_address=resolved_ip[:64] if resolved_ip else None,
            metadata_json=_sanitize_metadata(metadata),
        )
        with _db_lock:
            db.add(entry)
            if commit:
                db.commit()
                db.refresh(entry)
        return entry
    except Exception:  # noqa: BLE001
        with _db_lock:
            db.rollback()
        logger.warning("Không thể ghi nhật ký kiểm toán cho sự kiện %s", action, exc_info=True)
        return None


def list_audit_logs(
    db: Session,
    *,
    action: str | None = None,
    user_id: int | None = None,
    limit: int = 100,
) -> list[AuditLog]:
    """Liệt kê nhật ký kiểm toán mới nhất, hỗ trợ lọc theo `action` và `user_id`."""
    safe_limit = max(1, min(int(limit or 100), 500))
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action.strip().upper())
    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)
    return query.order_by(AuditLog.id.desc()).limit(safe_limit).all()
