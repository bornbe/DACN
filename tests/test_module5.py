"""
Kiểm thử auth, API scan, hủy scan CRAWLING/SCANNING, trusted proxy rate limiting,
giới hạn single-process, production secrets và khôi phục hàng đợi nền Module 5 - Issue #5.1/#5.2.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from app import create_app
from config.config import (
    DEFAULT_JWT_SECRET_KEY,
    DEFAULT_SECRET_KEY,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    validate_production_secrets,
    validate_single_process_config,
)
from core.crawler.bfs_crawler import CrawlResult
from core.crawler.form_parser import EndpointDescriptor
from core.scanners.base_scanner import BaseScanner, Finding
from models.base import Base
from models.scan_job import ScanSession, ScanStatus
from models.user import User
from services import scan_service
from tasks import scan_tasks
from tasks.recovery_tasks import clear_recovered_scan, recover_pending_scans


@pytest.fixture()
def client():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "module-five-test-secret-key-at-least-32-bytes",
            "RATE_LIMIT_MAX_REQUESTS": 100,
        }
    )
    engine = app.extensions["database_engine"]
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with app.test_client() as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


def register_and_login(
    client,
    username: str = "lab-user",
    email: str = "lab@example.test",
    password: str = "secure-pass-123",
) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert response.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
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

    factory = client.application.extensions["database_session_factory"]
    with factory() as db:
        stored = db.query(User).filter(User.username == "lab-user").first()
        assert stored is not None
        assert stored.role == "pentester"

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


def test_stop_scan_cancels_pending_and_worker_skips_execution(client):
    """Hủy scan PENDING -> CANCELLED; khi worker lấy job thì không thực thi ScanEngine."""
    _, headers = register_and_login(client)
    with patch("tasks.scan_tasks.submit"):
        created = client.post(
            "/api/scans",
            json={"url": "http://127.0.0.1:8080", "modules": ["headers"]},
            headers=headers,
        )
    session_id = created.get_json()["session_id"]

    # Người dùng khác gọi stop nhận 404 và không làm ảnh hưởng scan đang PENDING.
    _, stranger_headers = register_and_login(
        client, username="stranger", email="stranger@example.test", password="secure-pass-999"
    )
    assert client.post(f"/api/scans/{session_id}/stop", headers=stranger_headers).status_code == 404
    assert client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]["status"] == "PENDING"

    # Chủ sở hữu dừng phiên PENDING -> chuyển ngay sang CANCELLED.
    stop = client.post(f"/api/scans/{session_id}/stop", headers=headers)
    assert stop.status_code == 202
    assert stop.get_json()["status"] == "CANCELLED"
    scan_data = client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]
    assert scan_data["status"] == "CANCELLED"
    assert scan_data["end_time"] is not None

    # Cho worker lấy job sau khi đã hủy: ScanEngine.run không được chạy và status giữ nguyên CANCELLED.
    with patch("core.engine.scan_engine.ScanEngine.run") as engine_run:
        report = scan_service.run_scan(session_id)
        engine_run.assert_not_called()
    assert report.status == "CANCELLED"

    after_worker = client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]
    assert after_worker["status"] == "CANCELLED"
    assert after_worker["end_time"] is not None

    # Gọi stop sau khi scan đã kết thúc -> 409 Conflict và không đổi kết quả.
    conflict = client.post(f"/api/scans/{session_id}/stop", headers=headers)
    assert conflict.status_code == 409
    assert conflict.get_json()["status"] == "CANCELLED"


def test_stop_scan_while_crawling_stops_engine_and_persists_cancelled(client):
    """Hủy scan đang ở trạng thái CRAWLING phải gửi tín hiệu tới stop_event và lưu trạng thái CANCELLED."""
    _, headers = register_and_login(client)
    with patch("tasks.scan_tasks.submit"):
        created = client.post(
            "/api/scans",
            json={"url": "http://127.0.0.1:8080", "modules": ["headers"]},
            headers=headers,
        )
    session_id = created.get_json()["session_id"]

    entered_crawling = threading.Event()
    scanner_called = threading.Event()

    class BlockingCrawler:
        def __init__(self, base_url, max_depth=2, max_pages=100, timeout=10, on_progress=None):
            self.base_url = base_url
            self.on_progress = on_progress

        def crawl(self):
            if self.on_progress:
                self.on_progress(1, self.base_url)
            entered_crawling.set()
            with scan_service._running_lock:
                stop_event = scan_service._running_scans[session_id]
            assert stop_event.wait(timeout=3.0), "stop_event không được kích hoạt khi gọi /stop ở CRAWLING"
            if self.on_progress:
                self.on_progress(2, f"{self.base_url}/next")
            return CrawlResult(base_url=self.base_url, visited_urls=[self.base_url], endpoints=[])

    class UnreachedScanner(BaseScanner):
        name = "headers"

        def scan(self, endpoint):
            scanner_called.set()
            return []

    with (
        patch("core.engine.scan_engine.BFSCrawler", BlockingCrawler),
        patch("core.engine.scan_engine.load_scanner_class", return_value=UnreachedScanner),
    ):
        worker = threading.Thread(target=scan_service.run_scan, args=(session_id,))
        worker.start()
        assert entered_crawling.wait(timeout=3.0)

        current = client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]
        assert current["status"] == "CRAWLING"

        stop_resp = client.post(f"/api/scans/{session_id}/stop", headers=headers)
        assert stop_resp.status_code == 202
        assert stop_resp.get_json()["state"] == "cancelling"
        assert stop_resp.get_json()["status"] == "CRAWLING"

        worker.join(timeout=3.0)
        assert not worker.is_alive()

    assert not scanner_called.is_set(), "Giai đoạn SCANNING không được chạy sau khi hủy ở CRAWLING"
    final_scan = client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]
    assert final_scan["status"] == "CANCELLED"
    assert final_scan["progress"] < 100
    assert final_scan["end_time"] is not None
    assert final_scan["error_message"]

    # Gọi stop lần nữa sau khi đã CANCELLED trả về 409 Conflict và giữ nguyên trạng thái.
    again = client.post(f"/api/scans/{session_id}/stop", headers=headers)
    assert again.status_code == 409
    assert again.get_json()["status"] == "CANCELLED"


def test_stop_scan_while_scanning_stops_worker_and_prevents_completed_override(client):
    """Hủy scan đang ở SCANNING dừng scanner qua stop_event và không bị ghi đè thành COMPLETED."""
    _, owner_headers = register_and_login(client)
    _, other_headers = register_and_login(
        client, username="intruder", email="intruder@example.test", password="secure-pass-456"
    )

    with patch("tasks.scan_tasks.submit"):
        created = client.post(
            "/api/scans",
            json={"url": "http://127.0.0.1:8080", "modules": ["headers"]},
            headers=owner_headers,
        )
    session_id = created.get_json()["session_id"]

    entered_scanning = threading.Event()
    second_endpoint_scanned = threading.Event()

    class FastCrawler:
        def __init__(self, base_url, **kwargs):
            self.base_url = base_url

        def crawl(self):
            return CrawlResult(
                base_url=self.base_url,
                visited_urls=[self.base_url, f"{self.base_url}/page2"],
                endpoints=[
                    EndpointDescriptor(url=self.base_url, method="GET", params={"a": "1"}),
                    EndpointDescriptor(url=f"{self.base_url}/page2", method="GET", params={"b": "2"}),
                ],
            )

    class BlockingScanner(BaseScanner):
        name = "headers"

        def scan(self, endpoint):
            if endpoint.url.endswith("/page2"):
                second_endpoint_scanned.set()
                return []
            entered_scanning.set()
            assert self.stop_event is not None
            assert self.stop_event.wait(timeout=3.0), "Scanner không nhận được stop_event khi hủy ở SCANNING"
            return [Finding(vuln_name="ShouldNotComplete", severity="LOW", target_url=endpoint.url)]

    with (
        patch("core.engine.scan_engine.BFSCrawler", FastCrawler),
        patch("core.engine.scan_engine.load_scanner_class", return_value=BlockingScanner),
    ):
        worker = threading.Thread(target=scan_service.run_scan, args=(session_id,))
        worker.start()
        assert entered_scanning.wait(timeout=3.0)

        current = client.get(f"/api/scans/{session_id}", headers=owner_headers).get_json()["scan"]
        assert current["status"] == "SCANNING"

        # User khác gọi stop nhận 404 và không làm dừng scan của chủ sở hữu.
        forbidden = client.post(f"/api/scans/{session_id}/stop", headers=other_headers)
        assert forbidden.status_code == 404
        with scan_service._running_lock:
            assert not scan_service._running_scans[session_id].is_set()

        # Chủ sở hữu gọi stop -> kích hoạt stop_event và dừng worker.
        stop_resp = client.post(f"/api/scans/{session_id}/stop", headers=owner_headers)
        assert stop_resp.status_code == 202
        assert stop_resp.get_json()["state"] == "cancelling"
        assert stop_resp.get_json()["status"] == "SCANNING"

        worker.join(timeout=3.0)
        assert not worker.is_alive()

    assert not second_endpoint_scanned.is_set(), "Endpoint tiếp theo không được quét sau khi đã hủy"
    final_scan = client.get(f"/api/scans/{session_id}", headers=owner_headers).get_json()["scan"]
    assert final_scan["status"] == "CANCELLED"
    assert final_scan["progress"] < 100
    assert final_scan["end_time"] is not None
    assert final_scan["error_message"]


def test_each_scan_has_isolated_stop_event_and_completed_scan_rejects_stop(client):
    """Mỗi phiên quét dùng stop_event riêng; dừng phiên A không làm ảnh hưởng phiên B đang chạy."""
    _, headers = register_and_login(client)
    with patch("tasks.scan_tasks.submit"):
        scan_a = client.post(
            "/api/scans", json={"url": "http://127.0.0.1:8080", "modules": ["headers"]}, headers=headers
        ).get_json()["session_id"]
        scan_b = client.post(
            "/api/scans", json={"url": "http://127.0.0.1:8081", "modules": ["headers"]}, headers=headers
        ).get_json()["session_id"]

    scanning_a = threading.Event()
    scanning_b = threading.Event()
    release_scan_b = threading.Event()

    class FastCrawler:
        def __init__(self, base_url, **kwargs):
            self.base_url = base_url

        def crawl(self):
            return CrawlResult(base_url=self.base_url, visited_urls=[self.base_url], endpoints=[])

    class DualScanner(BaseScanner):
        name = "headers"

        def scan(self, endpoint):
            assert self.stop_event is not None
            if "8080" in endpoint.url:
                scanning_a.set()
                assert self.stop_event.wait(timeout=3.0)
            else:
                scanning_b.set()
                assert release_scan_b.wait(timeout=3.0)
                assert not self.stop_event.is_set()
            return []

    with (
        patch("core.engine.scan_engine.BFSCrawler", FastCrawler),
        patch("core.engine.scan_engine.load_scanner_class", return_value=DualScanner),
    ):
        t_a = threading.Thread(target=scan_service.run_scan, args=(scan_a,))
        t_b = threading.Thread(target=scan_service.run_scan, args=(scan_b,))
        t_a.start()
        t_b.start()
        assert scanning_a.wait(timeout=3.0)
        assert scanning_b.wait(timeout=3.0)

        with scan_service._running_lock:
            assert scan_service._running_scans[scan_a] is not scan_service._running_scans[scan_b]

        assert client.post(f"/api/scans/{scan_a}/stop", headers=headers).status_code == 202
        release_scan_b.set()

        t_a.join(timeout=3.0)
        t_b.join(timeout=3.0)

    state_a = client.get(f"/api/scans/{scan_a}", headers=headers).get_json()["scan"]
    state_b = client.get(f"/api/scans/{scan_b}", headers=headers).get_json()["scan"]
    assert state_a["status"] == "CANCELLED"
    assert state_b["status"] == "COMPLETED"
    assert state_b["progress"] == 100

    # Gọi stop trên phiên đã COMPLETED trả 409 và không làm thay đổi trạng thái COMPLETED.
    stop_completed = client.post(f"/api/scans/{scan_b}/stop", headers=headers)
    assert stop_completed.status_code == 409
    assert stop_completed.get_json()["status"] == "COMPLETED"
    assert client.get(f"/api/scans/{scan_b}", headers=headers).get_json()["scan"]["status"] == "COMPLETED"


def test_race_between_stop_and_worker_claim_and_idempotent_run_scan(client):
    """
    Khi worker vừa chuyển PENDING -> RUNNING ngay lúc endpoint /stop được gọi,
    stop_event đã được đăng ký trước nên tín hiệu hủy không bị mất; và gọi run_scan lần 2 không chạy lại engine.
    """
    _, headers = register_and_login(client)
    with patch("tasks.scan_tasks.submit"):
        session_id = client.post(
            "/api/scans", json={"url": "http://127.0.0.1:8080", "modules": ["headers"]}, headers=headers
        ).get_json()["session_id"]

    engine_starting = threading.Event()
    stop_called = threading.Event()
    original_init = scan_service.ScanEngine.__init__

    def hooked_init(self, context, db_session=None):
        original_init(self, context, db_session=db_session)
        engine_starting.set()
        assert stop_called.wait(timeout=3.0)

    with patch.object(scan_service.ScanEngine, "__init__", hooked_init):
        worker = threading.Thread(target=scan_service.run_scan, args=(session_id,))
        worker.start()
        assert engine_starting.wait(timeout=3.0)

        # Lúc này DB vừa chuyển sang RUNNING nhưng ScanEngine.run() chưa vào CRAWLING:
        stop_resp = client.post(f"/api/scans/{session_id}/stop", headers=headers)
        assert stop_resp.status_code == 202
        assert stop_resp.get_json()["status"] == "RUNNING"
        stop_called.set()

        worker.join(timeout=3.0)
        assert not worker.is_alive()

    final_state = client.get(f"/api/scans/{session_id}", headers=headers).get_json()["scan"]
    assert final_state["status"] == "CANCELLED"

    # Nếu run_scan được gọi lần nữa cho cùng session_id thì không thực thi lại ScanEngine.
    with patch("core.engine.scan_engine.ScanEngine.run") as engine_run:
        second_report = scan_service.run_scan(session_id)
        engine_run.assert_not_called()
    assert second_report.status == "CANCELLED"


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

    _, other_headers = register_and_login(
        client, username="other-user", email="other@example.test", password="secure-pass-456"
    )
    assert client.get(f"/api/scans/{session_id}", headers=other_headers).status_code == 404
    assert client.get(f"/api/scans/{session_id}/findings", headers=other_headers).status_code == 404


def test_rate_limiter_ignores_spoofed_xff_for_direct_or_untrusted_proxy():
    """
    Request trực tiếp hoặc từ proxy ngoài allowlist gửi X-Forwarded-For giả mạo
    vẫn phải bị rate limit theo remote_addr (kể cả khi TRUSTED_PROXY=True nhưng không có allowlist).
    """
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "RATE_LIMIT_MAX_REQUESTS": 2,
            "RATE_LIMIT_WINDOW_SECONDS": 60,
            "TRUSTED_PROXY": True,
            "TRUSTED_PROXIES": ("10.10.0.1",),
        }
    )
    with app.test_client() as c:
        # Client trực tiếp (198.51.100.25 không nằm trong TRUSTED_PROXIES) xoay vòng X-Forwarded-For:
        r1 = c.get("/api/health", environ_base={"REMOTE_ADDR": "198.51.100.25"}, headers={"X-Forwarded-For": "1.1.1.1"})
        r2 = c.get("/api/health", environ_base={"REMOTE_ADDR": "198.51.100.25"}, headers={"X-Forwarded-For": "2.2.2.2"})
        r3 = c.get("/api/health", environ_base={"REMOTE_ADDR": "198.51.100.25"}, headers={"X-Forwarded-For": "3.3.3.3"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429


def test_rate_limiter_extracts_client_ip_behind_trusted_proxy_and_isolates_quotas():
    """
    Request đi qua proxy thuộc TRUSTED_PROXIES được tính rate limit theo client IP thật;
    hai client khác nhau phía sau cùng trusted proxy có quota tách biệt.
    """
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "RATE_LIMIT_MAX_REQUESTS": 2,
            "RATE_LIMIT_WINDOW_SECONDS": 60,
            "TRUSTED_PROXIES": "10.0.0.0/24",
        }
    )
    proxy_env = {"REMOTE_ADDR": "10.0.0.5"}
    with app.test_client() as c:
        # Client A (203.0.113.10) qua trusted proxy (kể cả khi cố chèn IP giả ở đầu chuỗi XFF):
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.10"}).status_code == 200
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "8.8.8.8, 203.0.113.10"}).status_code == 200
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "7.7.7.7, 203.0.113.10"}).status_code == 429

        # Client B (203.0.113.20) đi qua cùng trusted proxy vẫn có quota riêng:
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "203.0.113.20"}).status_code == 200
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "203.0.113.20"}).status_code == 200
        assert c.get("/api/health", environ_base=proxy_env, headers={"X-Forwarded-For": "203.0.113.20"}).status_code == 429


def test_production_secrets_validation_and_env_isolation():
    """Production từ chối secret mặc định/rỗng/ngắn (<32) và chấp nhận secret mạnh; dev/test không bị chặn."""
    strong_secret = "s" * 32
    strong_jwt = "j" * 32

    # 1. Mặc định, rỗng, khoảng trắng hoặc ngắn (<32) đều bị từ chối:
    for bad_secret, bad_jwt in [
        (DEFAULT_SECRET_KEY, strong_jwt),
        (strong_secret, DEFAULT_JWT_SECRET_KEY),
        ("", strong_jwt),
        (strong_secret, ""),
        ("   " * 12, strong_jwt),
        ("short-secret", strong_jwt),
        (strong_secret, "short-jwt-key"),
    ]:
        with pytest.raises(RuntimeError):
            validate_production_secrets(bad_secret, bad_jwt)

    # 2. create_app ở production với secret mặc định/ngắn phải dừng khởi động:
    with pytest.raises(RuntimeError):
        create_app(
            {
                "APP_ENV": "production",
                "TESTING": False,
                "SECRET_KEY": DEFAULT_SECRET_KEY,
                "JWT_SECRET_KEY": strong_jwt,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            }
        )

    with pytest.raises(RuntimeError):
        create_app(ProductionConfig)

    # 3. Production chấp nhận secret hợp lệ:
    validate_production_secrets(strong_secret, strong_jwt)
    with patch("tasks.recovery_tasks.recover_pending_scans", return_value=0) as recover_mock:
        prod_app = create_app(
            {
                "APP_ENV": "production",
                "TESTING": False,
                "SECRET_KEY": strong_secret,
                "JWT_SECRET_KEY": strong_jwt,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            }
        )
        assert prod_app is not None
        recover_mock.assert_called_once()

    # 4. Development & Testing không bị chặn bởi secret mặc định:
    with patch("tasks.recovery_tasks.recover_pending_scans", return_value=0):
        dev_app = create_app(
            {
                "APP_ENV": "development",
                "TESTING": False,
                "SECRET_KEY": DEFAULT_SECRET_KEY,
                "JWT_SECRET_KEY": DEFAULT_JWT_SECRET_KEY,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            }
        )
        assert dev_app is not None
    test_app = create_app(TestingConfig)
    assert test_app is not None
    assert DevelopmentConfig.APP_ENV == "development"


def test_single_process_deployment_validation():
    """Xác nhận giới hạn single-process: từ chối cấu hình WORKER_PROCESSES > 1."""
    validate_single_process_config(1)
    with pytest.raises(RuntimeError):
        validate_single_process_config(2)
    with pytest.raises(RuntimeError):
        create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "WORKER_PROCESSES": 4,
            }
        )


def test_recover_pending_scans_recovers_only_interrupted_and_prevents_duplicates(client):
    """
    recover_pending_scans() khôi phục PENDING và RUNNING (đặt lại PENDING, progress=0),
    bỏ qua COMPLETED/CANCELLED/FAILED, và gọi nhiều lần không enqueue trùng cùng một scan.
    """
    _, headers = register_and_login(client)
    factory = client.application.extensions["database_session_factory"]

    with factory() as db:
        user = db.query(User).filter(User.username == "lab-user").first()
        assert user is not None
        s_pending = scan_service.create_scan(db, user.id, "http://127.0.0.1:8001", 1, ["headers"])
        s_running = scan_service.create_scan(db, user.id, "http://127.0.0.1:8002", 1, ["headers"])
        s_running.status = ScanStatus.RUNNING.value
        s_running.progress = 55

        s_completed = scan_service.create_scan(db, user.id, "http://127.0.0.1:8003", 1, ["headers"])
        s_completed.status = ScanStatus.COMPLETED.value
        s_completed.progress = 100
        s_completed.end_time = datetime.now(timezone.utc)

        s_cancelled = scan_service.create_scan(db, user.id, "http://127.0.0.1:8004", 1, ["headers"])
        s_cancelled.status = ScanStatus.CANCELLED.value
        s_cancelled.end_time = datetime.now(timezone.utc)

        db.commit()
        ids = (s_pending.id, s_running.id, s_completed.id, s_cancelled.id)

    try:
        with patch("tasks.scan_tasks.submit", return_value=True) as submit_mock:
            recovered_first = recover_pending_scans(factory)
            assert recovered_first == 2
            assert [call.args[0] for call in submit_mock.call_args_list] == [ids[0], ids[1]]

            # Gọi recovery lần thứ hai trong cùng process không được enqueue lại phiên đã recover:
            recovered_second = recover_pending_scans(factory)
            assert recovered_second == 0
            assert submit_mock.call_count == 2

        with factory() as db:
            refreshed_pending = db.get(ScanSession, ids[0])
            refreshed_running = db.get(ScanSession, ids[1])
            refreshed_completed = db.get(ScanSession, ids[2])
            refreshed_cancelled = db.get(ScanSession, ids[3])
            assert refreshed_pending.status == ScanStatus.PENDING.value
            assert refreshed_running.status == ScanStatus.PENDING.value
            assert refreshed_running.progress == 0
            assert refreshed_completed.status == ScanStatus.COMPLETED.value
            assert refreshed_cancelled.status == ScanStatus.CANCELLED.value
    finally:
        for sid in ids:
            clear_recovered_scan(sid)


def test_submit_deduplicates_queued_session_id():
    """Hàng đợi scan không nhận trùng cùng một session_id khi job đó đang chờ xử lý."""
    fake_id = 999_991
    with scan_tasks._worker_lock:
        scan_tasks._queued_or_active.add(fake_id)
    try:
        assert scan_tasks.submit(fake_id) is False
    finally:
        with scan_tasks._worker_lock:
            scan_tasks._queued_or_active.discard(fake_id)


def test_recovery_failure_rolls_back_db_and_logs_on_startup(client, caplog):
    """
    Khi recovery gặp lỗi DB khi commit, trạng thái RUNNING không bị cập nhật dở dang,
    không có job nào bị submit và create_app ghi log lỗi mà không làm sập khởi động.
    """
    _, _ = register_and_login(client)
    factory = client.application.extensions["database_session_factory"]

    with factory() as db:
        user = db.query(User).filter(User.username == "lab-user").first()
        scan = scan_service.create_scan(db, user.id, "http://127.0.0.1:8005", 1, ["headers"])
        scan.status = ScanStatus.RUNNING.value
        scan.progress = 42
        db.commit()
        scan_id = scan.id

    real_session = factory()
    failing_factory = MagicMock()

    def make_failing_session():
        s = factory()
        s.commit = MagicMock(side_effect=RuntimeError("DB commit failed during recovery"))
        return s

    failing_factory.side_effect = make_failing_session
    failing_factory.kw = factory.kw
    real_session.close()

    with patch("tasks.scan_tasks.submit") as submit_mock:
        with pytest.raises(RuntimeError, match="DB commit failed"):
            recover_pending_scans(failing_factory)
        submit_mock.assert_not_called()

    # DB vẫn giữ nguyên trạng thái RUNNING và progress=42 (đã rollback an toàn).
    with factory() as db:
        unchanged = db.get(ScanSession, scan_id)
        assert unchanged.status == ScanStatus.RUNNING.value
        assert unchanged.progress == 42

    # Khi khởi động app (TESTING=False), lỗi recovery được bắt và log, không làm sập create_app.
    with patch("tasks.recovery_tasks.recover_pending_scans", side_effect=RuntimeError("boom")):
        app = create_app(
            {
                "APP_ENV": "development",
                "TESTING": False,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            }
        )
        assert app is not None
    assert "Không thể khôi phục hàng đợi scan khi khởi động." in caplog.text
