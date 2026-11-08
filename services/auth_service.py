"""
Dịch vụ xác thực và JWT cho Web API - Issue #5.1.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from flask import current_app, has_app_context
from sqlalchemy.orm import Session

from config.config import Config
from models.user import User

TOKEN_LIFETIME = timedelta(hours=1)


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Xác thực tài khoản đang hoạt động bằng username và mật khẩu."""
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active or not user.check_password(password):
        return None
    return user


def generate_token(user: User) -> str:
    """Tạo access token HS256 có thời hạn một giờ."""
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "exp": now + TOKEN_LIFETIME,
    }
    secret = current_app.config["JWT_SECRET_KEY"] if has_app_context() else Config.JWT_SECRET_KEY
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any] | None:
    """Giải mã và xác minh chữ ký, thuật toán, thời hạn của JWT."""
    try:
        secret = current_app.config["JWT_SECRET_KEY"] if has_app_context() else Config.JWT_SECRET_KEY
        payload = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload