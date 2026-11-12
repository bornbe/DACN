"""
Kiểm thử đơn vị cho SQLiScanner (Error-based & Boolean-based) - Issue #3.4 & #7.2.
Sử dụng máy chủ HTTP cục bộ (127.0.0.1) và mock Session, tuyệt đối không gọi ra mạng ngoài.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from core.crawler.form_parser import EndpointDescriptor
from core.scanners.sqli_scanner import SQLiScanner


class _SQLiLabHandler(BaseHTTPRequestHandler):
    """Mục tiêu giả lập trên loopback 127.0.0.1 cho các kịch bản SQLi."""

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if parsed.path == "/error-sqli":
            item_id = params.get("id", "1")
            if "'" in item_id or '"' in item_id:
                body = (
                    "<html><body>Database error: You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version.</body></html>"
                )
            else:
                body = f"<html><body>Product detail for id={item_id}</body></html>"
        elif parsed.path == "/bool-sqli":
            q = params.get("id", "1")
            if "1=2" in q or "'1'='2" in q:
                body = "<html><body>No item found.</body></html>"
            else:
                body = (
                    "<html><body><h1>Item #1: Enterprise Firewall Appliance</h1>"
                    "<p>Detailed technical specification and inventory status available in stock.</p>"
                    "<p> Category: Network Security Hardware - SKU: FW-9000-PRO </p></body></html>"
                )
        else:
            body = "<html><body>Safe static content page.</body></html>"

        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = {k: v[0] for k, v in parse_qs(raw).items()}
        username = params.get("username", "")
        if "'" in username:
            body = "<html><body>sqlite3.OperationalError: near \"'\": syntax error</body></html>"
        else:
            body = "<html><body>Login failed.</body></html>"

        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


@pytest.fixture(scope="module")
def sqli_server_url():
    server = HTTPServer(("127.0.0.1", 0), _SQLiLabHandler)
    base_url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield base_url
    server.shutdown()
    server.server_close()


def test_sqli_scanner_detects_error_based_get_and_post(sqli_server_url: str) -> None:
    scanner = SQLiScanner(timeout=5)

    get_ep = EndpointDescriptor(
        url=f"{sqli_server_url}/error-sqli",
        method="GET",
        params={"id": "1"},
    )
    get_findings = scanner.scan(get_ep)
    assert any(f.vuln_name == "SQL Injection (Error-based)" for f in get_findings)
    err_finding = next(f for f in get_findings if f.vuln_name == "SQL Injection (Error-based)")
    assert err_finding.severity == "HIGH"
    assert err_finding.parameter == "id"
    assert err_finding.cwe_id == "CWE-89"

    post_ep = EndpointDescriptor(
        url=f"{sqli_server_url}/login",
        method="POST",
        params={"username": "admin"},
    )
    post_findings = scanner.scan(post_ep)
    assert any(f.vuln_name == "SQL Injection (Error-based)" for f in post_findings)


def test_sqli_scanner_detects_boolean_based_and_ignores_safe_endpoint(sqli_server_url: str) -> None:
    scanner = SQLiScanner(timeout=5)

    bool_ep = EndpointDescriptor(
        url=f"{sqli_server_url}/bool-sqli",
        method="GET",
        params={"id": "1"},
    )
    bool_findings = scanner.scan(bool_ep)
    assert any(f.vuln_name == "SQL Injection (Boolean-based)" for f in bool_findings)

    safe_ep = EndpointDescriptor(
        url=f"{sqli_server_url}/safe",
        method="GET",
        params={"q": "hello"},
    )
    assert scanner.scan(safe_ep) == []
    assert scanner.scan(EndpointDescriptor(url=f"{sqli_server_url}/safe", method="GET", params={})) == []
