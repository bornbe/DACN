"""
Kiểm thử SafeHTTPClient và kiểm soát chuyển hướng (Redirect / SSRF Protection) - Yêu cầu #2.
Chỉ sử dụng máy chủ HTTP giả lập trên loopback (127.0.0.1) và mock Session, tuyệt đối không gọi ra Internet.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock

import pytest
import requests

from core.scanners.ssrf_scanner import SSRFScanner, SSRFScannerUnsupportedError
from core.security.target_validator import SSRFBlockedError, TargetValidationError
from core.utils.safe_http_client import SafeHTTPClient


class _RedirectLabHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect-to-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/redirect-to-external":
            self.send_response(302)
            self.send_header("Location", "http://example.com/internal")
            self.end_headers()
        elif self.path == "/redirect-to-other-port":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/secret")
            self.end_headers()
        elif self.path == "/redirect-in-scope":
            self.send_response(302)
            self.send_header("Location", "/safe-landing")
            self.end_headers()
        elif self.path == "/safe-landing":
            body = b"loopback-safe-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def redirect_lab_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectLabHandler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield base_url
    server.shutdown()
    server.server_close()


def test_safe_http_client_blocks_direct_non_loopback_without_network_call():
    mock_session = MagicMock(spec=requests.Session)
    mock_session.headers = {}
    client = SafeHTTPClient(session=mock_session)

    for forbidden_url in (
        "http://example.com/admin",
        "https://8.8.8.8/dns",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/router",
        "http://10.0.0.1/internal",
        "http://172.16.0.1/private",
        "http://0.0.0.0:8000/",
        "http://[::]/",
    ):
        with pytest.raises(SSRFBlockedError):
            client.get(forbidden_url)

    mock_session.request.assert_not_called()


def test_safe_http_client_forbids_disabling_tls_verification():
    mock_session = MagicMock(spec=requests.Session)
    mock_session.headers = {}
    client = SafeHTTPClient(session=mock_session)

    with pytest.raises(TargetValidationError, match="verify=False"):
        client.get("http://127.0.0.1:8080/", verify=False)

    mock_session.request.assert_not_called()


def test_safe_http_client_blocks_unsafe_redirects_and_allows_in_scope_loopback(redirect_lab_url: str):
    client = SafeHTTPClient(timeout=5)

    # Redirect tới cloud metadata (169.254.169.254) bị chặn cứng
    with pytest.raises(SSRFBlockedError):
        client.get(f"{redirect_lab_url}/redirect-to-metadata")

    # Redirect tới miền ngoài Internet (example.com) bị chặn cứng
    with pytest.raises(SSRFBlockedError):
        client.get(f"{redirect_lab_url}/redirect-to-external")

    # Redirect sang cổng khác ngoài scope gốc cũng bị chặn
    with pytest.raises(SSRFBlockedError):
        client.get(f"{redirect_lab_url}/redirect-to-other-port")

    # Redirect hợp lệ trong cùng origin loopback thành công
    resp = client.get(f"{redirect_lab_url}/redirect-in-scope")
    assert resp.status_code == 200
    assert resp.text == "loopback-safe-ok"


def test_ssrf_oob_scanner_is_disabled_and_sends_no_requests():
    from core.crawler.form_parser import EndpointDescriptor

    mock_session = MagicMock(spec=requests.Session)
    mock_session.headers = {}
    scanner = SSRFScanner(session=mock_session)

    with pytest.raises(SSRFScannerUnsupportedError, match="vô hiệu hóa"):
        scanner.scan(EndpointDescriptor(url="http://127.0.0.1:8080/fetch", method="GET", params={"url": "x"}))

    mock_session.request.assert_not_called()
