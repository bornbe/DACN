"""
HTTP endpoints đăng ký và đăng nhập - Issue #5.1.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from flask.typing import ResponseReturnValue
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from schemas.auth_schema import validate_login, validate_register
from services.auth_service import authenticate, generate_token
from services.user_service import create_user

auth_blueprint = Blueprint("auth", __name__, url_prefix="/api/auth")


def _session_factory() -> sessionmaker[Session]:
    return current_app.extensions["database_session_factory"]


@auth_blueprint.post("/login")
def login() -> ResponseReturnValue:
    """Đăng nhập và trả về JWT cùng thông tin công khai của người dùng."""
    try:
        credentials = validate_login(request.get_json(silent=True))
    except ValueError as exc:
        return jsonify(error="Bad Request", message=str(exc)), 400

    with _session_factory()() as db:
        user = authenticate(db, credentials["username"], credentials["password"])
        if user is None:
            return jsonify(error="Unauthorized", message="Tên đăng nhập hoặc mật khẩu không đúng."), 401
        token = generate_token(user)
        return jsonify(access_token=token, token_type="Bearer", user=user.to_dict()), 200


@auth_blueprint.post("/register")
def register() -> ResponseReturnValue:
    """Tạo tài khoản quyền pentester; tài khoản mới không thể tự chọn role."""
    try:
        values = validate_register(request.get_json(silent=True))
    except ValueError as exc:
        return jsonify(error="Bad Request", message=str(exc)), 400

    with _session_factory()() as db:
        try:
            user = create_user(db, **values)
        except IntegrityError:
            db.rollback()
            return jsonify(error="Conflict", message="Username hoặc email đã được sử dụng."), 409
        return jsonify(user=user.to_dict()), 201