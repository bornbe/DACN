"""
Kiểm thử tích hợp & bảo mật cho các nâng cấp nền tảng Automated Pentest Platform:
1. Cloudflare Tunnel (`CF-Connecting-IP` + `ProxyFix` có điều kiện theo `TRUSTED_PROXIES`).
2. Self-Scan Guard cho `APP_BASE_URL` (`okiaconpet.cloud`) mà không ảnh hưởng Lab `127.0.0.1`.
3. Phân quyền RBAC (`admin` vs `tester`/`pentester`) và quản trị người dùng.
4. Target Management & xác minh quyền sở hữu (`WELL_KNOWN`, `DNS_TXT`, `ADMIN_APPROVED`) + `TARGET_VERIFICATION_REQUIRED`.
5. Audit Logging (tự động che thông tin nhạy cảm).
6. So sánh lịch sử quét (`Scan Diffing`: `new`, `fixed`, `persistent`) & chuẩn hóa `source_tool`.
7. Xuất báo cáo đa định dạng (`HTML` chống XSS + CSP, `JSON` chuẩn hóa) & lưu bảng `Report`.
8. Tự động bổ sung cột mới trên SQLite cũ (`_ensure_sqlite_columns`).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import request
from sqlalchemy import create_engine, inspect, text

from app import create_app
from core.crawler.url_parser import URLParser
from core.scanners.security_headers_scanner import SecurityHeadersScanner
from models.audit_log import AuditLog
from models.base import Base, init_db
from models.report import Report
from models.scan_job import ScanStatus
from models.user import User
from models.vulnerability import VulnerabilityFinding
from services import audit_service, scan_service, target_service


@pytest.fixture()
def app_instance():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "platform-upgrades-jwt-secret-key-min-32-chars",
            "RATE_LIMIT_MAX_REQUESTS": 200,
            "TARGET_VERIFICATION_REQUIRED": True,
        }
    )
    engine = app.extensions["database_engine"]
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield app
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(app_instance):
    with app_instance.test_client() as test_client:
        yield test_client


def _create_user_and_token(
    client,
    username: str,
    email: str,
    role: str = "pentester",
    password: str = "StrongPass!123",
) -> tuple[int, dict[str, str]]:
    reg = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert reg.status_code == 201
    user_id = reg.get_json()["user"]["id"]

    if role != "pentester":
        factory = client.application.extensions["database_session_factory"]
        with factory() as db:
            user = db.get(User, user_id)
            assert user is not None
            user.role = role
            db.commit()

    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    token = login.get_json()["access_token"]
    return user_id, {"Authorization": f"Bearer {token}"}


def test_cloudflare_tunnel_cf_connecting_ip_and_conditional_proxy_fix():
    """Chỉ tin CF-Connecting-IP và X-Forwarded-Proto/Host khi REMOTE_ADDR thuộc TRUSTED_PROXIES."""
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "RATE_LIMIT_MAX_REQUESTS": 2,
            "RATE_LIMIT_WINDOW_SECONDS": 60,
            "TRUSTED_PROXIES": "172.28.0.0/16,127.0.0.1/32",
        }
    )

    @app.get("/api/echo-meta")
    def echo_meta():
        return {"scheme": request.scheme, "host": request.host, "remote_addr": request.remote_addr}, 200

    with app.test_client() as c:
        # 1. Đi qua cloudflared (172.28.0.5): nhận đúng scheme=https, host=okiaconpet.cloud và quota theo CF-Connecting-IP
        cf_env = {"REMOTE_ADDR": "172.28.0.5"}
        cf_headers_a = {
            "CF-Connecting-IP": "198.51.100.77",
            "X-Forwarded-For": "1.2.3.4, 198.51.100.77",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "okiaconpet.cloud",
        }
        r1 = c.get("/api/echo-meta", environ_base=cf_env, headers=cf_headers_a)
        assert r1.status_code == 200
        assert r1.get_json() == {
            "scheme": "https",
            "host": "okiaconpet.cloud",
            "remote_addr": "172.28.0.5",
        }
        assert c.get("/api/echo-meta", environ_base=cf_env, headers=cf_headers_a).status_code == 200
        # Request thứ 3 từ cùng CF-Connecting-IP bị chặn 429:
        assert c.get("/api/echo-meta", environ_base=cf_env, headers=cf_headers_a).status_code == 429

        # Người dùng khác qua cùng cloudflared có quota độc lập:
        cf_headers_b = {
            "CF-Connecting-IP": "203.0.113.88",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "okiaconpet.cloud",
        }
        assert c.get("/api/echo-meta", environ_base=cf_env, headers=cf_headers_b).status_code == 200

        # 2. Kết nối trực tiếp ngoài TRUSTED_PROXIES cố giả mạo CF-Connecting-IP & X-Forwarded-Host:
        untrusted_env = {"REMOTE_ADDR": "198.51.100.200"}
        spoof1 = c.get(
            "/api/echo-meta",
            environ_base=untrusted_env,
            headers={
                "CF-Connecting-IP": "8.8.8.8",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "evil.example",
            },
        )
        assert spoof1.status_code == 200
        assert spoof1.get_json()["scheme"] == "http"
        assert spoof1.get_json()["host"] != "evil.example"
        assert (
            c.get(
                "/api/echo-meta",
                environ_base=untrusted_env,
                headers={"CF-Connecting-IP": "8.8.4.4"},
            ).status_code
            == 200
        )
        assert (
            c.get(
                "/api/echo-meta",
                environ_base=untrusted_env,
                headers={"CF-Connecting-IP": "1.1.1.1"},
            ).status_code
            == 429
        )


def test_self_scan_guard_excludes_platform_api_only_on_app_base_url():
    """Chặn tự crawl `/api/` và `/scans/` trên `okiaconpet.cloud`, giữ nguyên cho lab `127.0.0.1`."""
    prod_parser = URLParser("https://okiaconpet.cloud")
    assert prod_parser.is_crawlable("https://okiaconpet.cloud/") is True
    assert prod_parser.is_crawlable("https://okiaconpet.cloud/products?id=1") is True
    assert prod_parser.is_crawlable("https://okiaconpet.cloud/api/scans") is False
    assert prod_parser.is_crawlable("https://okiaconpet.cloud/api/health") is False
    assert prod_parser.is_crawlable("https://okiaconpet.cloud/scans/12") is False

    lab_parser = URLParser("http://127.0.0.1:3000")
    assert lab_parser.is_crawlable("http://127.0.0.1:3000/api/Products") is True
    assert lab_parser.is_crawlable("http://127.0.0.1:3000/scans/demo") is True


def test_rbac_admin_endpoints_and_audit_log_sanitization(client):
    tester_id, tester_headers = _create_user_and_token(client, "tester1", "tester1@example.test", role="tester")
    admin_id, admin_headers = _create_user_and_token(client, "admin1", "admin1@example.test", role="admin")

    # Tester bị chặn 403 khi truy cập API quản trị:
    assert client.get("/api/admin/users", headers=tester_headers).status_code == 403
    assert client.get("/api/admin/audit-logs", headers=tester_headers).status_code == 403
    assert (
        client.patch(f"/api/admin/users/{tester_id}", json={"role": "admin"}, headers=tester_headers).status_code
        == 403
    )

    # Admin xem danh sách người dùng và nâng/hạ quyền user khác:
    users_resp = client.get("/api/admin/users", headers=admin_headers)
    assert users_resp.status_code == 200
    assert len(users_resp.get_json()["users"]) == 2

    promote = client.patch(f"/api/admin/users/{tester_id}", json={"role": "admin"}, headers=admin_headers)
    assert promote.status_code == 200
    assert promote.get_json()["user"]["role"] == "admin"

    # Admin không thể tự hạ quyền hoặc tự khóa chính mình:
    assert (
        client.patch(f"/api/admin/users/{admin_id}", json={"role": "tester"}, headers=admin_headers).status_code
        == 400
    )
    assert (
        client.patch(f"/api/admin/users/{admin_id}", json={"is_active": False}, headers=admin_headers).status_code
        == 400
    )

    # Kiểm tra AuditLog không bao giờ lưu mật khẩu/token nhạy cảm:
    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        audit_service.record_audit_log(
            db,
            action="CUSTOM_TEST",
            user_id=admin_id,
            metadata={"safe_key": "visible", "password": "secret", "verification_token": "tok"},
        )
    logs_resp = client.get("/api/admin/audit-logs?limit=50", headers=admin_headers)
    assert logs_resp.status_code == 200
    logs = logs_resp.get_json()["audit_logs"]
    actions = {entry["action"] for entry in logs}
    assert {"USER_REGISTER", "LOGIN_SUCCESS", "ADMIN_USER_UPDATE", "CUSTOM_TEST"}.issubset(actions)
    raw_dump = json.dumps(logs)
    assert "StrongPass!123" not in raw_dump
    assert '"password"' not in raw_dump
    assert '"verification_token"' not in raw_dump


def test_target_verification_workflow_enforced_before_scanning(client):
    tester_id, tester_headers = _create_user_and_token(client, "sec_tester", "sec@example.test", role="tester")
    _, admin_headers = _create_user_and_token(client, "sec_admin", "secadmin@example.test", role="admin")

    # 1. Không cho khai báo mục tiêu ngoài phạm vi cho phép:
    bad_target = client.post("/api/targets", json={"url": "https://example.com"}, headers=tester_headers)
    assert bad_target.status_code == 400

    # 2. Khi TARGET_VERIFICATION_REQUIRED=True, quét mục tiêu chưa xác minh bị chặn 403:
    unverified_scan = client.post(
        "/api/scans",
        json={"url": "http://127.0.0.1:8080", "modules": ["headers"], "max_depth": 1},
        headers=tester_headers,
    )
    assert unverified_scan.status_code == 403

    # 3. Khai báo target hợp lệ -> nhận trạng thái PENDING + verification_token:
    created_target = client.post(
        "/api/targets",
        json={"name": "Local DVWA", "url": "http://127.0.0.1:8080", "scope": {"allowed_paths": ["/"], "max_depth": 2}},
        headers=tester_headers,
    )
    assert created_target.status_code == 201
    target_info = created_target.get_json()["target"]
    target_id = target_info["id"]
    token = target_info["verification_token"]
    assert target_info["authorization_status"] == "PENDING"
    assert token

    # Vẫn bị chặn khi target còn PENDING:
    still_blocked = client.post(
        "/api/scans",
        json={"url": "http://127.0.0.1:8080/login", "modules": ["headers"], "max_depth": 1},
        headers=tester_headers,
    )
    assert still_blocked.status_code == 403

    # 4. Xác minh qua WELL_KNOWN với nội dung sai -> 422; nội dung chứa đúng token -> 200 VERIFIED:
    fake_http = MagicMock()
    fake_http.get.return_value = SimpleNamespace(status_code=200, text="wrong-token")
    with patch("services.target_service.SafeHTTPClient", return_value=fake_http):
        fail_verify = client.post(
            f"/api/targets/{target_id}/verify",
            json={"method": "WELL_KNOWN"},
            headers=tester_headers,
        )
        assert fail_verify.status_code == 422

    fake_http.get.return_value = SimpleNamespace(status_code=200, text=f"owner-verify={token}\n")
    with patch("services.target_service.SafeHTTPClient", return_value=fake_http):
        ok_verify = client.post(
            f"/api/targets/{target_id}/verify",
            json={"method": "WELL_KNOWN"},
            headers=tester_headers,
        )
        assert ok_verify.status_code == 200
        assert ok_verify.get_json()["target"]["authorization_status"] == "VERIFIED"

    # 5. Sau khi VERIFIED, tester tạo scan trên origin đó thành công (202):
    with patch("tasks.scan_tasks.submit") as mock_submit:
        allowed_scan = client.post(
            "/api/scans",
            json={"url": "http://127.0.0.1:8080/vulnerabilities", "modules": ["headers"], "max_depth": 1},
            headers=tester_headers,
        )
        assert allowed_scan.status_code == 202
        mock_submit.assert_called_once()

    # 6. Kiểm tra xác minh DNS_TXT và Admin Approve/Reject trên target domain ủy quyền:
    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        dom_target = target_service.create_target(
            db,
            owner_id=tester_id,
            url="https://okiaconpet.cloud",
            name="Production Domain",
        )
        dom_id = dom_target.id
        dom_token = dom_target.verification_token or ""
        verified_dns = target_service.verify_target_ownership(
            db,
            dom_id,
            user_id=tester_id,
            method="DNS_TXT",
            txt_lookup=lambda qname: [f"v=pentest1 token={dom_token}"] if qname == "_pentest-verify.okiaconpet.cloud" else [],
        )
        assert verified_dns.authorization_status == "VERIFIED"
        assert verified_dns.verification_method == "DNS_TXT"

    reject_resp = client.post(f"/api/targets/{dom_id}/reject", headers=admin_headers)
    assert reject_resp.status_code == 200
    assert reject_resp.get_json()["target"]["authorization_status"] == "REJECTED"

    approve_resp = client.post(f"/api/targets/{dom_id}/approve", headers=admin_headers)
    assert approve_resp.status_code == 200
    assert approve_resp.get_json()["target"]["authorization_status"] == "APPROVED"


def test_scan_diffing_html_json_reports_and_source_tool(client):
    owner_id, owner_headers = _create_user_and_token(client, "diff_owner", "diff@example.test")
    _, other_headers = _create_user_and_token(client, "diff_other", "otherdiff@example.test")

    # Kiểm tra BaseScanner.make_finding tự gán source_tool:
    hdr_scanner = SecurityHeadersScanner()
    sample_finding = hdr_scanner.make_finding("Missing Header", "http://127.0.0.1:8080")
    assert sample_finding.source_tool == "headers_scanner"

    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        scan_a = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8080", max_depth=2, modules=["sqli", "xss", "headers"]
        )
        scan_b = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8080", max_depth=2, modules=["sqli", "xss", "headers"]
        )
        scan_a.status = ScanStatus.COMPLETED.value
        scan_b.status = ScanStatus.COMPLETED.value

        # Scan A có 2 lỗi (SQLi tại q -> sẽ được fix ở B; Missing CSP -> còn tồn tại ở B)
        db.add(
            VulnerabilityFinding(
                session_id=scan_a.id,
                vuln_type="SQL Injection (Error-based)",
                severity="HIGH",
                target_url="http://127.0.0.1:8080/search",
                param="q",
                payload="'",
                evidence="SQL syntax error",
                cwe_id="CWE-89",
                source_tool="sqli_scanner",
            )
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan_a.id,
                vuln_type="Missing Security Header: Content-Security-Policy",
                severity="MEDIUM",
                target_url="http://127.0.0.1:8080",
                source_tool="headers_scanner",
            )
        )

        # Scan B giữ lỗi Missing CSP (persistent) và phát sinh lỗi XSS mới chứa ký tự nguy hiểm
        db.add(
            VulnerabilityFinding(
                session_id=scan_b.id,
                vuln_type="Missing Security Header: Content-Security-Policy",
                severity="MEDIUM",
                target_url="http://127.0.0.1:8080",
                source_tool="headers_scanner",
            )
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan_b.id,
                vuln_type="Reflected XSS <img src=x onerror=alert(1)>",
                severity="HIGH",
                target_url="http://127.0.0.1:8080/comment",
                param="msg",
                payload="<script>alert(1)</script>",
                evidence="Unescaped <script>alert(1)</script>",
                cwe_id="CWE-79",
                source_tool="xss_scanner",
            )
        )
        db.commit()
        id_a, id_b = scan_a.id, scan_b.id

    # 1. So sánh Scan A -> Scan B:
    cmp_resp = client.get(f"/api/scans/compare?base={id_a}&target={id_b}", headers=owner_headers)
    assert cmp_resp.status_code == 200
    comp = cmp_resp.get_json()["comparison"]
    assert comp["summary"]["new_count"] == 1
    assert comp["summary"]["fixed_count"] == 1
    assert comp["summary"]["persistent_count"] == 1
    assert comp["new_findings"][0]["source_tool"] == "xss_scanner"
    assert comp["fixed_findings"][0]["vuln_type"] == "SQL Injection (Error-based)"

    # Người dùng khác không được so sánh scan không thuộc sở hữu:
    assert client.get(f"/api/scans/compare?base={id_a}&target={id_b}", headers=other_headers).status_code == 404

    # 2. Tải báo cáo JSON:
    json_resp = client.get(f"/api/scans/{id_b}/report?format=json", headers=owner_headers)
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.content_type
    parsed_json = json.loads(json_resp.get_data(as_text=True))
    assert parsed_json["session_id"] == id_b
    assert parsed_json["summary"]["total_findings"] == 2
    assert {f["source_tool"] for f in parsed_json["findings"]} == {"headers_scanner", "xss_scanner"}

    # 3. Tải báo cáo HTML (kiểm tra escape chống XSS + CSP header):
    html_resp = client.get(f"/api/scans/{id_b}/report?format=html", headers=owner_headers)
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.content_type
    assert "default-src 'none'" in html_resp.headers.get("Content-Security-Policy", "")
    html_body = html_resp.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_body
    assert "xss_scanner" in html_body

    # 4. Xác nhận bản ghi Report và AuditLog REPORT_EXPORT đã được lưu vào CSDL:
    with factory() as db:
        reports = db.query(Report).filter(Report.session_id == id_b).all()
        assert {r.report_format for r in reports} == {"json", "html"}
        export_logs = db.query(AuditLog).filter(AuditLog.action == "REPORT_EXPORT").all()
        assert len(export_logs) == 2


def test_sqlite_legacy_schema_auto_adds_missing_columns(tmp_path):
    """Đảm bảo tệp SQLite cũ thiếu cột mới vẫn được init_db tự động nâng cấp không mất dữ liệu."""
    db_file = tmp_path / "legacy_scanner.db"
    uri = f"sqlite:///{db_file}"
    legacy_engine = create_engine(uri)
    with legacy_engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE scan_targets ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "name VARCHAR(150) NOT NULL, "
                "url TEXT NOT NULL, "
                "description TEXT, "
                "created_at DATETIME, "
                "updated_at DATETIME)"
            )
        )
        conn.execute(text("INSERT INTO scan_targets (name, url) VALUES ('legacy', 'encrypted_dummy')"))
    legacy_engine.dispose()

    upgraded_engine = init_db(uri)
    cols = {c["name"] for c in inspect(upgraded_engine).get_columns("scan_targets")}
    assert {"owner_id", "scope", "authorization_status", "verification_token", "verification_method"}.issubset(cols)
    with upgraded_engine.connect() as conn:
        row = conn.execute(text("SELECT name, authorization_status FROM scan_targets WHERE name='legacy'")).fetchone()
        assert row is not None
        assert row[0] == "legacy"
        assert row[1] == "PENDING"
    upgraded_engine.dispose()


def test_postgresql_dialect_auto_adds_missing_columns_ddl():
    """F-01: Đảm bảo _ensure_missing_columns sinh đúng DDL `ADD COLUMN IF NOT EXISTS` cho PostgreSQL."""
    from models.base import _ensure_missing_columns

    executed_sql: list[str] = []
    fake_conn = MagicMock()
    fake_conn.execute.side_effect = lambda clause: executed_sql.append(str(clause))

    fake_begin_ctx = MagicMock()
    fake_begin_ctx.__enter__.return_value = fake_conn
    fake_begin_ctx.__exit__.return_value = False

    fake_engine = MagicMock()
    fake_engine.dialect.name = "postgresql"
    fake_engine.begin.return_value = fake_begin_ctx

    fake_inspector = MagicMock()
    fake_inspector.get_table_names.return_value = ["scan_targets", "vulnerability_findings"]
    fake_inspector.get_columns.side_effect = lambda tbl: (
        [{"name": "id"}, {"name": "name"}, {"name": "url"}]
        if tbl == "scan_targets"
        else [{"name": "id"}, {"name": "vuln_type"}]
    )

    with patch("models.base.inspect", return_value=fake_inspector):
        added = _ensure_missing_columns(fake_engine)

    assert "scan_targets.owner_id" in added
    assert "scan_targets.authorization_status" in added
    assert "vulnerability_findings.source_tool" in added
    assert all("ADD COLUMN IF NOT EXISTS" in stmt for stmt in executed_sql)


def test_admin_scan_access_consistency_across_list_detail_findings_and_stop(client):
    """F-02: Admin truy cập nhất quán list, detail, findings và stop đối với phiên quét của user khác."""
    owner_id, _ = _create_user_and_token(client, "scan_owner", "scanowner@example.test", role="tester")
    _, stranger_headers = _create_user_and_token(client, "scan_stranger", "scanstranger@example.test", role="tester")
    _, admin_headers = _create_user_and_token(client, "scan_admin", "scanadmin@example.test", role="admin")

    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        scan = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8080", max_depth=1, modules=["headers"]
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan.id,
                vuln_type="Missing Security Header: X-Frame-Options",
                severity="LOW",
                target_url="http://127.0.0.1:8080",
                source_tool="headers_scanner",
            )
        )
        db.commit()
        session_id = scan.id

    # User thường khác vẫn bị chặn 404 trên toàn bộ endpoint:
    assert client.get(f"/api/scans/{session_id}", headers=stranger_headers).status_code == 404
    assert client.get(f"/api/scans/{session_id}/findings", headers=stranger_headers).status_code == 404
    assert client.post(f"/api/scans/{session_id}/stop", headers=stranger_headers).status_code == 404
    assert client.get("/api/scans", headers=stranger_headers).get_json()["scans"] == []

    # Admin xem được trong danh sách, xem chi tiết, xem findings và dừng phiên PENDING của user khác:
    admin_list = client.get("/api/scans", headers=admin_headers)
    assert admin_list.status_code == 200
    assert any(s["id"] == session_id for s in admin_list.get_json()["scans"])

    admin_detail = client.get(f"/api/scans/{session_id}", headers=admin_headers)
    assert admin_detail.status_code == 200
    assert admin_detail.get_json()["scan"]["id"] == session_id

    admin_findings = client.get(f"/api/scans/{session_id}/findings", headers=admin_headers)
    assert admin_findings.status_code == 200
    assert len(admin_findings.get_json()["findings"]) == 1

    admin_stop = client.post(f"/api/scans/{session_id}/stop", headers=admin_headers)
    assert admin_stop.status_code == 202
    assert admin_stop.get_json()["status"] == "CANCELLED"


def test_result_manager_persist_findings_preserves_source_tool(client):
    """F-03: ResultManager.persist_findings lưu đúng trường source_tool vào CSDL."""
    from core.engine.result_manager import ResultManager
    from core.scanners.base_scanner import Finding

    owner_id, _ = _create_user_and_token(client, "rm_user", "rm@example.test")
    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        scan = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8080", max_depth=1, modules=["sqli"]
        )
        rm = ResultManager()
        rm.add(
            Finding(
                vuln_name="SQL Injection (Error-based)",
                severity="HIGH",
                target_url="http://127.0.0.1:8080/item",
                parameter="id",
                source_tool="sqli_scanner",
            )
        )
        saved = rm.persist_findings(db, scan.id)
        assert saved == 1

        stored = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.session_id == scan.id).first()
        assert stored is not None
        assert stored.source_tool == "sqli_scanner"


def test_bfs_crawler_collects_query_params_after_in_scope_redirect():
    """F-04: Khi URL gốc chuyển hướng trong scope tới URL đích có query string, BFSCrawler thu thập được tham số."""
    from core.crawler.bfs_crawler import BFSCrawler

    fake_http = MagicMock()
    fake_http.get.return_value = SimpleNamespace(
        status_code=200,
        url="http://127.0.0.1:8080/catalog?category=security&page=1",
        headers={"Content-Type": "text/html; charset=utf-8"},
        text="<html><body><h1>Catalog</h1></body></html>",
        encoding="utf-8",
        apparent_encoding="utf-8",
    )

    crawler = BFSCrawler("http://127.0.0.1:8080/start", max_depth=1, http_client=fake_http)
    result = crawler.crawl()
    matched = [
        ep
        for ep in result.endpoints
        if ep.url == "http://127.0.0.1:8080/catalog" and ep.method == "GET"
    ]
    assert len(matched) == 1
    assert matched[0].params == {"category": "security", "page": "1"}


def test_compare_scans_metadata_and_sqli_boolean_confirmation_probe(client):
    """F-06: Kiểm tra cảnh báo different_targets, previous_severity và confirmation probe chống nhiễu SQLi."""
    from core.crawler.form_parser import EndpointDescriptor
    from core.scanners.sqli_scanner import SQLiScanner

    owner_id, owner_headers = _create_user_and_token(client, "f06_user", "f06@example.test")
    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        scan_1 = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8080", max_depth=1, modules=["headers"]
        )
        scan_2 = scan_service.create_scan(
            db, user_id=owner_id, url="http://127.0.0.1:8090", max_depth=1, modules=["headers"]
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan_1.id,
                vuln_type="Weak Header",
                severity="LOW",
                target_url="http://127.0.0.1:8080",
            )
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan_2.id,
                vuln_type="Weak Header",
                severity="HIGH",
                target_url="http://127.0.0.1:8080",
            )
        )
        db.commit()
        s1_id, s2_id = scan_1.id, scan_2.id

    resp = client.get(f"/api/scans/compare?base={s1_id}&target={s2_id}", headers=owner_headers)
    assert resp.status_code == 200
    comp = resp.get_json()["comparison"]
    assert comp["summary"]["different_targets"] is True
    assert comp["persistent_findings"][0]["previous_severity"] == "LOW"
    assert comp["persistent_findings"][0]["severity"] == "HIGH"

    # Kiểm tra confirmation probe của SQLiScanner:
    scanner = SQLiScanner()
    ep = EndpointDescriptor(url="http://127.0.0.1:8080/item", method="GET", params={"id": "1"})
    baseline_html = "<html><body>Item #1 Detailed Product Description Static Block AAAA BBBB CCCC</body></html>"
    short_noise = "<html><body>Empty</body></html>"

    # Kịch bản 1: Nhiễu tạm thời (lần 1 FALSE khác biệt, nhưng lần confirm FALSE lại giống baseline) -> bỏ qua FP:
    flaky_responses = iter(
        [
            SimpleNamespace(text=baseline_html),  # baseline
            SimpleNamespace(text=baseline_html),  # error probe '
            SimpleNamespace(text=baseline_html),  # error probe "
            SimpleNamespace(text=baseline_html),  # pair 1 TRUE
            SimpleNamespace(text=short_noise),    # pair 1 FALSE (nhiễu tạm thời)
            SimpleNamespace(text=baseline_html),  # confirm pair 1 TRUE
            SimpleNamespace(text=baseline_html),  # confirm pair 1 FALSE (trở lại bình thường -> bác bỏ FP)
            SimpleNamespace(text=baseline_html),  # pair 2 TRUE
            SimpleNamespace(text=baseline_html),  # pair 2 FALSE
        ]
    )
    with patch.object(scanner, "_send_values", side_effect=lambda *_a, **_kw: next(flaky_responses)):
        assert scanner.scan(ep) == []

    # Kịch bản 2: Lỗ hổng thật (cả lần đầu và lần confirm đều tái hiện sai khác TRUE/FALSE) -> ghi nhận Finding:
    consistent_responses = iter(
        [
            SimpleNamespace(text=baseline_html),  # baseline
            SimpleNamespace(text=baseline_html),  # error probe '
            SimpleNamespace(text=baseline_html),  # error probe "
            SimpleNamespace(text=baseline_html),  # pair 1 TRUE
            SimpleNamespace(text=short_noise),    # pair 1 FALSE
            SimpleNamespace(text=baseline_html),  # confirm pair 1 TRUE
            SimpleNamespace(text=short_noise),    # confirm pair 1 FALSE -> xác nhận Boolean SQLi
        ]
    )
    with patch.object(scanner, "_send_values", side_effect=lambda *_a, **_kw: next(consistent_responses)):
        detected = scanner.scan(ep)
        assert len(detected) == 1
        assert detected[0].vuln_name == "SQL Injection (Boolean-based)"
        assert "confirm=" in (detected[0].evidence or "")
