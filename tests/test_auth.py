"""
Kiểm thử đơn vị và tích hợp cho hệ thống xác thực người dùng & JWT (`tests/test_auth.py`).
Kiểm tra đăng ký, đăng nhập đúng/sai mật khẩu, tài khoản bị khóa, tính hợp lệ/hết hạn của JWT
và phân quyền trên các API bảo vệ bởi `@require_auth`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app import create_app
from models.base import Base
from models.user import User
from services.auth_service import decode_token, generate_token


@pytest.fixture()
def auth_client():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "test-auth-jwt-secret-key-at-least-32-bytes-long",
            "RATE_LIMIT_MAX_REQUESTS": 100,
        }
    )
    engine = app.extensions["database_engine"]
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with app.test_client() as client:
        yield client
    Base.metadata.drop_all(bind=engine)


def test_register_validation_and_duplicate_rejection(auth_client):
    # Thiếu thông tin hoặc mật khẩu quá ngắn -> 400
    assert auth_client.post("/api/auth/register", json={"username": "ab", "email": "a@b.c", "password": "123"}).status_code == 400
    assert auth_client.post("/api/auth/register", json={"username": "validuser", "email": "bad-email", "password": "password123"}).status_code == 400

    # Đăng ký hợp lệ -> 201, luôn gán role='pentester' dù client gửi role='admin'
    ok = auth_client.post(
        "/api/auth/register",
        json={"username": "pentester01", "email": "p01@example.test", "password": "StrongPassword123", "role": "admin"},
    )
    assert ok.status_code == 201
    user_payload = ok.get_json()["user"]
    assert user_payload["username"] == "pentester01"
    assert user_payload["role"] == "pentester"
    assert "password_hash" not in user_payload

    # Đăng ký trùng username hoặc email -> 409
    dup = auth_client.post(
        "/api/auth/register",
        json={"username": "pentester01", "email": "other@example.test", "password": "StrongPassword123"},
    )
    assert dup.status_code == 409


def test_login_right_wrong_password_and_inactive_user(auth_client):
    auth_client.post(
        "/api/auth/register",
        json={"username": "alice", "email": "alice@example.test", "password": "CorrectPassword!123"},
    )

    # Sai mật khẩu -> 401
    wrong_pw = auth_client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "WrongPassword!999"},
    )
    assert wrong_pw.status_code == 401

    # Đúng mật khẩu -> 200 kèm access_token hợp lệ
    right_pw = auth_client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "CorrectPassword!123"},
    )
    assert right_pw.status_code == 200
    token = right_pw.get_json()["access_token"]
    assert isinstance(token, str) and len(token) > 20

    # Vô hiệu hóa tài khoản -> cả login và dùng lại JWT cũ đều bị từ chối 401
    factory = auth_client.application.extensions["database_session_factory"]
    with factory() as db:
        user = db.query(User).filter(User.username == "alice").first()
        assert user is not None
        user.is_active = False
        db.commit()

    assert (
        auth_client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "CorrectPassword!123"},
        ).status_code
        == 401
    )
    assert (
        auth_client.get(
            "/api/scans",
            headers={"Authorization": f"Bearer {token}"},
        ).status_code
        == 401
    )


def test_jwt_token_verification_tampering_and_expiration(auth_client):
    app = auth_client.application
    factory = app.extensions["database_session_factory"]
    with factory() as db:
        user = User(username="bob", email="bob@example.test", role="pentester")
        user.set_password("BobSecurePass123")
        db.add(user)
        db.commit()
        db.refresh(user)

        with app.app_context():
            valid_token = generate_token(user)
            decoded = decode_token(valid_token)
            assert decoded is not None
            assert decoded["user_id"] == user.id
            assert decoded["username"] == "bob"

            # Token hết hạn -> decode_token trả None và API trả 401
            expired_token = jwt.encode(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "role": user.role,
                    "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
                },
                app.config["JWT_SECRET_KEY"],
                algorithm="HS256",
            )
            assert decode_token(expired_token) is None

            # Token ký sai khóa bí mật -> decode_token trả None
            forged_token = jwt.encode(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "role": "admin",
                    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
                },
                "wrong-secret-key-not-matching-application-secret",
                algorithm="HS256",
            )
            assert decode_token(forged_token) is None

    assert auth_client.get("/api/scans", headers={"Authorization": f"Bearer {expired_token}"}).status_code == 401
    assert auth_client.get("/api/scans", headers={"Authorization": f"Bearer {forged_token}"}).status_code == 401
    assert auth_client.get("/api/scans", headers={"Authorization": f"Bearer {valid_token}"}).status_code == 200
