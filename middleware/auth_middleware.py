"""
Xác minh JWT cho các route cần đăng nhập - Issue #5.1.
"""

from __future__ import annotations

from functools import wraps
from typing import Callable, ParamSpec

from flask import current_app, g, jsonify, request
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from services.auth_service import decode_token
from services.user_service import get_by_id

P = ParamSpec("P")


def require_auth(view: Callable[P, ResponseReturnValue]) -> Callable[P, ResponseReturnValue]:
    """Đọc Bearer token, xác thực người dùng và gắn User vào flask.g."""
    @wraps(view)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> ResponseReturnValue:
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token.strip():
            return jsonify(error="Unauthorized", message="Cần gửi Authorization: Bearer <token>."), 401

        payload = decode_token(token.strip())
        user_id = payload.get("user_id") if payload else None
        if not isinstance(user_id, int) or isinstance(user_id, bool):
            return jsonify(error="Unauthorized", message="Token không hợp lệ hoặc đã hết hạn."), 401

        factory: sessionmaker[Session] = current_app.extensions["database_session_factory"]
        with factory() as db:
            user = get_by_id(db, user_id)
            if user is None or not user.is_active:
                return jsonify(error="Unauthorized", message="Tài khoản không tồn tại hoặc đã bị vô hiệu hóa."), 401
            g.user = user
            return view(*args, **kwargs)

    return wrapped