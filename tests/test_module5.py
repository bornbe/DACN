"""
Kiểm thử auth, API scan và hàng đợi nền Module 5 - Issue #5.1/#5.2.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app import create_app
from models.base import Base


@pytest.fixture()
def client():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "module-five-test-secret",
            "RATE_LIMIT_MAX_REQUESTS": 100,
        }
    )
    engine = app.extensions["database_engine"]
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with app.test_client() as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


def register_and_login(client) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/api/auth/register",
        json={"username": "lab-user", "email": "lab@example.test", "password": "secure-pass-123"},
    )
    assert response.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": "lab-user", "password": "secure-pass-123"},
    )
    assert login.status_code == 200
    token = login.get_json()["access_token"]
    return token, {"Authorization": f"Bearer {token}"}


def test_register_login_and_invalid_credentials(client):
    assert client.post("/api/auth/login", json={"username": "missing", "password": "invalid"}).status_code == 401

    response = client.post(
        "/api/auth/register",
        json={"username": "lab-user", "email": "lab@example.test", "password": "secure-pass-123", "role": "admin"},
    )
    assert response.status_code == 201
    assert response.get_json()["user"]["role"] == "pentester"
    assert "password_hash" not in response.get_json()["user"]

    login = client.post(
        "/api/auth/login",
        json={"username": "lab-user", "password": "secure-pass-123"},
    )
    assert login.status_code == 200
    assert login.get_json()["token_type"] == "Bearer"


def test_scan_api_requires_auth_validates_scope_and_returns_user_scans(client):
    assert client.get("/api/scans").status_code == 401
    token, headers = register_and_login(client)
    assert token

    invalid_target = client.post("/api/scans", json={"url": "https://example.com"}, headers=headers)
    assert invalid_target.status_code == 400

    invalid_module = client.post(
        "/api/scans",
        json={"url": "http://127.0.0.1:8080", "modules": ["not-a-module"]},
        headers=headers,
    )
    assert invalid_module.status_code == 400

    with patch("tasks.scan_tasks.submit") as submit:
        created = client.post(
            "/api/scans",
            json={"url": "http://127.0.0.1:8080", "max_depth": 1, "modules": ["headers"]},
            headers=headers,
        )
    assert created.status_code == 202
    body = created.get_json()
    assert body["status"] == "PENDING"
    submit.assert_called_once_with(body["session_id"])

    session_id = body["session_id"]
    details = client.get(f"/api/scans/{session_id}", headers=headers)
    assert details.status_code == 200
    assert details.get_json()["scan"]["progress"] == 0

    findings = client.get(f"/api/scans/{session_id}/findings", headers=headers)
    assert findings.status_code == 200
    assert findings.get_json() == {"findings": []}

    listing = client.get("/api/scans", headers=headers)
    assert listing.status_code == 200
    assert [scan["id"] for scan in listing.get_json()["scans"]] == [session_id]


def test_scans_are_private_to_their_owner(client):
    owner_token, owner_headers = register_and_login(client)
    assert owner_token
    with patch("tasks.scan_tasks.submit"):
        created = client.post(
            "/api/scans",
            json={"url": "http://localhost:9000"},
            headers=owner_headers,
        )
    session_id = created.get_json()["session_id"]

    other = client.post(
        "/api/auth/register",
        json={"username": "other-user", "email": "other@example.test", "password": "secure-pass-456"},
    )
    assert other.status_code == 201
    other_login = client.post(
        "/api/auth/login",
        json={"username": "other-user", "password": "secure-pass-456"},
    )
    other_headers = {"Authorization": f"Bearer {other_login.get_json()['access_token']}"}

    assert client.get(f"/api/scans/{session_id}", headers=other_headers).status_code == 404
    assert client.get(f"/api/scans/{session_id}/findings", headers=other_headers).status_code == 404
