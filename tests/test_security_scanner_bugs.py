"""
Kiểm thử hồi quy cho 4 hạng mục bảo mật và chất lượng phát hiện lỗ hổng của Scanner:
1. URL sai định dạng trong BaseScanner.send() không làm văng exception hoặc gửi request.
2. Redirect 3xx ra ngoài scope bị chặn trước khi gửi request đến đích; kiểm soát MAX_REDIRECTS.
3. XSSScanner phân loại thận trọng phản chiếu (plain text, HTML-escaped, ngữ cảnh rủi ro, thiếu Content-Type).
4. Mask dữ liệu nhạy cảm trong payload/evidence của Finding, ResultManager và lưu trữ DB.
Toàn bộ kiểm thử chỉ dùng HTTP server nội bộ (127.0.0.1) hoặc response giả lập.
"""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import requests

from core.crawler.form_parser import EndpointDescriptor
from core.engine.result_manager import ResultManager
from core.scanners.base_scanner import Finding
from core.scanners.sqli_scanner import SQLiScanner
from core.scanners.xss_scanner import XSSScanner
from core.security.data_sanitizer import mask_sensitive_data
from models import Base, ScanSession, ScanTarget, VulnerabilityFinding, get_session_factory, init_db


def make_response(body: str, content_type: str | None = "text/html; charset=utf-8") -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    if content_type is not None:
        response.headers["Content-Type"] = content_type
    return response


class _Server:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "_Server":
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class TestMalformedURLHandling(unittest.TestCase):
    """Mục 1: URL gốc hoặc URL redirect sai định dạng không làm BaseScanner.send() văng exception."""

    def test_invalid_port_url_returns_none_without_request(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        scanner = SQLiScanner(session=session)

        result = scanner.send("GET", "http://example.com:invalid/")

        self.assertIsNone(result)
        session.request.assert_not_called()

    def test_invalid_ipv6_url_returns_none_without_request(self) -> None:
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        scanner = XSSScanner(session=session)

        result = scanner.send("GET", "http://[invalid/")

        self.assertIsNone(result)
        session.request.assert_not_called()

    def test_malformed_redirect_location_returns_none_safely(self) -> None:
        for bad_location in ("http://example.com:invalid/path", "http://[invalid/path"):
            with self.subTest(location=bad_location):
                class BadRedirectHandler(BaseHTTPRequestHandler):
                    def do_GET(self) -> None:  # noqa: N802
                        self.send_response(302)
                        self.send_header("Location", bad_location)
                        self.send_header("Content-Length", "0")
                        self.end_headers()

                    def log_message(self, *args: object) -> None:
                        pass

                with _Server(BadRedirectHandler) as srv:
                    result = SQLiScanner().send("GET", f"http://127.0.0.1:{srv.port}/start")
                    self.assertIsNone(result)

    def test_valid_url_still_sends_request_normally(self) -> None:
        received: list[str] = []

        class OkHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                received.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:
                pass

        with _Server(OkHandler) as srv:
            resp = SQLiScanner().send("GET", f"http://127.0.0.1:{srv.port}/hello", params={"a": "1"})
            self.assertIsNotNone(resp)
            self.assertEqual(resp.text, "ok")
        self.assertEqual(received, ["/hello?a=1"])


class TestOutOfScopeRedirect(unittest.TestCase):
    """Mục 2: Chặn redirect ra ngoài scope, hỗ trợ redirect trong scope và giới hạn MAX_REDIRECTS."""

    def test_no_request_to_out_of_scope_host(self) -> None:
        hits: list[str] = []

        class Out(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                hits.append(self.path)
                body = b"You have an error in your SQL syntax; xsscanary<>\"'"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        with _Server(Out) as out:
            target = f"http://127.0.0.1:{out.port}/trap"

            class In(BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # noqa: N802
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, *args: object) -> None:
                    pass

            with _Server(In) as inn:
                ep = EndpointDescriptor(url=f"http://127.0.0.1:{inn.port}/p", method="GET", params={"q": "1"})
                self.assertEqual(SQLiScanner().scan(ep), [])
                self.assertEqual(XSSScanner(canary_token="xsscanary").scan(ep), [])
        self.assertEqual(hits, [])

    def test_in_scope_redirect_followed(self) -> None:
        seen_paths: list[str] = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen_paths.append(self.path)
                if self.path.startswith("/a"):
                    self.send_response(302)
                    self.send_header("Location", "/b")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")

            def log_message(self, *args: object) -> None:
                pass

        with _Server(H) as s:
            r = SQLiScanner().send("GET", f"http://127.0.0.1:{s.port}/a", params={"k": "v"})
            self.assertIsNotNone(r)
            self.assertEqual(r.text, "ok")
        # Request đầu tiên giữ nguyên query params; bước redirect theo URL đích tương đối
        self.assertEqual(seen_paths, ["/a?k=v", "/b"])

    def test_allow_redirects_false_does_not_follow(self) -> None:
        seen_paths: list[str] = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen_paths.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/b")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        with _Server(H) as s:
            r = SQLiScanner().send("GET", f"http://127.0.0.1:{s.port}/a", allow_redirects=False)
            self.assertIsNotNone(r)
            self.assertEqual(r.status_code, 302)
        self.assertEqual(seen_paths, ["/a"])

    def test_redirect_loop_exceeding_max_redirects_returns_none(self) -> None:
        hits: list[str] = []

        class LoopHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/loop")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: object) -> None:
                pass

        with _Server(LoopHandler) as s:
            r = SQLiScanner().send("GET", f"http://127.0.0.1:{s.port}/loop")
            self.assertIsNone(r)
        self.assertEqual(len(hits), 6)  # 1 request gốc + 5 lần redirect tối đa


class TestXSSReflectionClassification(unittest.TestCase):
    """Mục 3: Phân loại thận trọng phản chiếu XSS."""

    TOKEN = "xsstoken123"

    def run_scan(self, body: str, content_type: str | None = "text/html") -> list[Finding]:
        scanner = XSSScanner(canary_token=self.TOKEN)
        ep = EndpointDescriptor(url="http://127.0.0.1:1/x", method="GET", params={"q": "1"})
        with patch.object(scanner, "send", return_value=make_response(body, content_type)):
            return scanner.scan(ep)

    def test_plain_text(self) -> None:
        self.assertEqual(self.run_scan(self.TOKEN + "<>\"'", "text/plain"), [])
        self.assertEqual(self.run_scan(f'{{"q": "{self.TOKEN}<>\'"}}', "application/json"), [])

    def test_html_escaped(self) -> None:
        self.assertEqual(self.run_scan(f"<p>{self.TOKEN}&lt;&gt;&quot;&#x27;</p>"), [])

    def test_unencoded_html_needs_review(self) -> None:
        f = self.run_scan(f"<p>{self.TOKEN}<>\"'</p>")
        self.assertEqual(len(f), 1)
        self.assertNotEqual(f[0].vuln_name, "Reflected XSS")
        self.assertEqual(f[0].vuln_name, "Unencoded Input Reflection (Needs Review)")
        self.assertIn(f[0].severity, ("LOW", "INFO"))
        self.assertIn("HTML", f[0].evidence)

    def test_unencoded_attribute(self) -> None:
        f = self.run_scan(f'<input value="{self.TOKEN}<>"\'">')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].vuln_name, "Unencoded Input Reflection (Needs Review)")
        self.assertIn("attribute", f[0].evidence)
        # Trong attribute có dấu nháy kép nhưng ký tự nháy bị mã hóa (chỉ còn <>): không thoát được attribute
        self.assertEqual(self.run_scan(f'<input value="{self.TOKEN}<>&quot;&#x27;">'), [])

    def test_javascript_context_classification(self) -> None:
        f = self.run_scan(f"<script>var a = '{self.TOKEN}<>\"'';</script>")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].vuln_name, "Unencoded Input Reflection (Needs Review)")
        self.assertIn("JavaScript", f[0].evidence)

    def test_missing_content_type_sniffs_html_safely(self) -> None:
        # Phản hồi thực sự có cấu trúc HTML nhưng thiếu Content-Type -> vẫn phát hiện reflection cần review
        html_no_ct = f"<!DOCTYPE html><html><body><div>{self.TOKEN}<>\"'</div></body></html>"
        f = self.run_scan(html_no_ct, content_type=None)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].vuln_name, "Unencoded Input Reflection (Needs Review)")

        # Văn bản thuần không có Content-Type (chỉ chứa canary + probe) -> không báo nhầm
        plain_no_ct = f"Echo result: {self.TOKEN}<>\"'"
        self.assertEqual(self.run_scan(plain_no_ct, content_type=None), [])


class TestEvidenceMasking(unittest.TestCase):
    """Mục 4: Mask thông tin nhạy cảm trong payload/evidence ở Finding, ResultManager và DB."""

    SECRETS = (
        "fake_bearer_token_val_101",
        "fake_session_cookie_val_202",
        "fake_api_token_val_303",
        "fake_password_val_404",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake_jwt_sig_505",
    )

    def body(self) -> str:
        return (
            "SQL syntax near Authorization: Bearer fake_bearer_token_val_101 in MySQL\n"
            "Set-Cookie: sid=fake_session_cookie_val_202; HttpOnly\n"
            'token="fake_api_token_val_303" password=fake_password_val_404\n'
            "jwt_raw=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake_jwt_sig_505\n"
            "<p>xsscanary<>\"'</p>\n"
        )

    def test_masked_in_finding_result_manager_and_db(self) -> None:
        ep = EndpointDescriptor(
            url="http://127.0.0.1:1/x",
            method="GET",
            params={"q": "token=fake_api_token_val_303"},
        )
        sqli, xss = SQLiScanner(), XSSScanner(canary_token="xsscanary")
        with patch.object(sqli, "send", return_value=make_response(self.body())), \
                patch.object(xss, "send", return_value=make_response(self.body())):
            fs = sqli.scan(ep) + xss.scan(ep)

        # Ngay khi tạo Finding, secret trong evidence và payload đã bị mask
        for f in fs:
            for s in self.SECRETS:
                self.assertNotIn(s, f.evidence or "")
                self.assertNotIn(s, f.payload or "")

        rm = ResultManager()
        for f in fs:
            rm.add(f)
        out = rm.findings
        names = {f.vuln_name for f in out}
        self.assertIn("SQL Injection (Error-based)", names)
        self.assertIn("Unencoded Input Reflection (Needs Review)", names)
        for f in out:
            self.assertEqual(f.parameter, "q")
            for s in self.SECRETS:
                self.assertNotIn(s, f.evidence or "")
                self.assertNotIn(s, f.payload or "")
        self.assertTrue(all("[REDACTED]" in (f.evidence or "") for f in out))

        # Kiểm tra lưu xuống DB qua ResultManager.persist_findings
        engine = init_db("sqlite:///:memory:")
        db = get_session_factory(engine)()
        try:
            target = ScanTarget(name="t", url="http://127.0.0.1:1")
            db.add(target)
            db.flush()
            scan_sess = ScanSession(target_id=target.id)
            db.add(scan_sess)
            db.flush()
            rm.persist_findings(db, scan_sess.id)

            stored = db.query(VulnerabilityFinding).filter_by(session_id=scan_sess.id).all()
            self.assertEqual(len(stored), len(out))
            for row in stored:
                for s in self.SECRETS:
                    self.assertNotIn(s, row.evidence or "")
                    self.assertNotIn(s, row.payload or "")
                self.assertIn("[REDACTED]", row.evidence or "")
        finally:
            db.close()
            Base.metadata.drop_all(bind=engine)

    def test_sanitizer_handles_none_empty_and_idempotency(self) -> None:
        self.assertIsNone(mask_sensitive_data(None))
        self.assertEqual(mask_sensitive_data(""), "")
        sample = 'Authorization: Bearer fake_tok_999\napi_key="fake_key_888"'
        once = mask_sensitive_data(sample)
        twice = mask_sensitive_data(once)
        self.assertEqual(once, twice)
        self.assertNotIn("fake_tok_999", once)
        self.assertNotIn("fake_key_888", once)
        self.assertIn("[REDACTED]", once)


if __name__ == "__main__":
    unittest.main()
