"""
Kiểm thử các cải tiến: Anti-CSRF đa nguồn (3.3), reset trạng thái theo phiên của Security Headers (3.2)
và hành vi Engine khi không còn module hợp lệ (Module 4).
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from core.crawler.form_parser import EndpointDescriptor
from core.engine import ScanContext, ScanEngine
from core.scanners.csrf_scanner import CSRFScanner, is_weak_token
from core.scanners.security_headers_scanner import SecurityHeadersScanner
from scanner import main as cli_main

TOKEN = "Xk39dKsl20sdKj3lSd9QwErTy"

# path -> (danh sách header (tên, giá trị), nội dung HTML)
ROUTES: dict[str, tuple[list[tuple[str, str]], str]] = {
    "/hidden": ([], f'<form action="/post" method="POST"><INPUT TYPE="HIDDEN" name="CSRF_Token" value="{TOKEN}"><input name="msg"></form>'),
    "/weak": ([], '<form action="/post" method="POST"><input type="hidden" name="csrf_token" value=""><input name="msg"></form>'),
    "/meta": ([], f'<html><head><meta name="csrf-token" content="{TOKEN}"></head><body><form action="/post" method="POST"><input name="msg"></form></body></html>'),
    "/cookie": ([("Set-Cookie", "XSRF-TOKEN=abc123def456; Path=/")], '<form action="/post" method="POST"><input name="msg"></form>'),
    "/header": ([("X-CSRF-Token", TOKEN)], '<form action="/post" method="POST"><input name="msg"></form>'),
    "/samesite": ([("Set-Cookie", "sid=abc; Path=/; SameSite=Lax")], '<form action="/post" method="POST"><input name="msg"></form>'),
    "/plain": ([], '<form action="/post" method="POST"><input name="msg"></form>'),
    "/method": ([], '<form action="/post" method="POST"><input type="hidden" name="_method" value="DELETE"><input name="id"></form>'),
    "/broken": ([], "<<form action=/post method=POST><input name='x' <div"),
    "/": ([], "<html><body>root</body></html>"),
}


class State:
    hits: list[str] = []
    lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        with State.lock:
            State.hits.append(self.path)
        headers, body = ROUTES.get(self.path, ([], "<html></html>"))
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args) -> None:
        pass


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        with State.lock:
            State.hits.clear()

    def hits(self, path: str) -> int:
        with State.lock:
            return State.hits.count(path)


class TestCSRFMultiSource(ServerCase):
    def post_ep(self, page: str, params: dict | None = None, method: str = "POST") -> EndpointDescriptor:
        return EndpointDescriptor(
            url=self.base + "/post", method=method, params=params if params is not None else {"msg": ""},
            page_url=self.base + page,
        )

    def scan(self, ep: EndpointDescriptor, static: bool = False):
        return CSRFScanner(check_static_token=static).scan(ep)

    def test_token_in_hidden_input_not_in_params(self) -> None:
        # type="HIDDEN" viết hoa, tên khác hoa/thường, token không có trong params
        self.assertEqual(self.scan(self.post_ep("/hidden")), [])

    def test_weak_hidden_token_reported(self) -> None:
        findings = self.scan(self.post_ep("/weak"))
        self.assertEqual(findings[0].vuln_name, "Anti-CSRF Token Empty or Weak")

    def test_token_only_in_meta(self) -> None:
        self.assertEqual(self.scan(self.post_ep("/meta")), [])

    def test_token_only_in_cookie_or_header(self) -> None:
        self.assertEqual(self.scan(self.post_ep("/cookie")), [])
        self.assertEqual(self.scan(self.post_ep("/header")), [])

    def test_samesite_only_is_downgraded_not_missing(self) -> None:
        findings = self.scan(self.post_ep("/samesite"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "INFO")
        self.assertNotEqual(findings[0].vuln_name, "Anti-CSRF Token Missing")
        self.assertIn("SameSite", findings[0].evidence)

    def test_post_form_without_token_is_missing(self) -> None:
        findings = self.scan(self.post_ep("/plain"))
        self.assertEqual([f.vuln_name for f in findings], ["Anti-CSRF Token Missing"])
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_get_form_is_ignored_without_request(self) -> None:
        findings = self.scan(self.post_ep("/plain", method="GET"))
        self.assertEqual(findings, [])
        self.assertEqual(self.hits("/plain"), 0)

    def test_method_override_delete(self) -> None:
        findings = self.scan(self.post_ep("/method", params={"_method": "DELETE", "id": ""}))
        self.assertEqual(findings[0].vuln_name, "Anti-CSRF Token Missing")
        self.assertIn("DELETE", findings[0].evidence)
        # override về GET => không còn là form thay đổi trạng thái
        self.assertEqual(self.scan(self.post_ep("/method", params={"_method": "GET"})), [])

    def test_broken_html_does_not_crash(self) -> None:
        findings = self.scan(self.post_ep("/broken", params={"x": ""}))
        self.assertEqual(findings[0].vuln_name, "Anti-CSRF Token Missing")

    def test_parser_exception_falls_back_to_params(self) -> None:
        with mock.patch("core.scanners.csrf_scanner.BeautifulSoup", side_effect=Exception("parse error")):
            ok = self.scan(self.post_ep("/plain", params={"csrf_token": TOKEN}))
            missing = self.scan(self.post_ep("/plain", params={"msg": ""}))
        self.assertEqual(ok, [])
        self.assertEqual(missing[0].vuln_name, "Anti-CSRF Token Missing")

    def test_network_error_does_not_crash(self) -> None:
        ep = EndpointDescriptor(url="http://127.0.0.1:1/post", method="POST", params={"a": ""})
        findings = CSRFScanner(timeout=1, check_static_token=False).scan(ep)
        self.assertEqual(findings[0].vuln_name, "Anti-CSRF Token Missing")
        self.assertIn("không xác minh", findings[0].evidence)

    def test_page_fetched_once_per_scan_and_reset(self) -> None:
        scanner = CSRFScanner(check_static_token=False)
        scanner.scan(self.post_ep("/plain", params={"a": ""}))
        scanner.scan(self.post_ep("/plain", params={"b": ""}))
        self.assertEqual(self.hits("/plain"), 1)
        scanner.reset()
        scanner.scan(self.post_ep("/plain", params={"a": ""}))
        self.assertEqual(self.hits("/plain"), 2)

    def test_weak_token_entropy(self) -> None:
        self.assertTrue(is_weak_token("aaaaaaaaaaaa"))
        self.assertTrue(is_weak_token("short"))
        self.assertFalse(is_weak_token(TOKEN))


class TestHeadersSessionState(ServerCase):
    def ep(self, path: str = "/") -> EndpointDescriptor:
        return EndpointDescriptor(url=self.base + path)

    def test_same_instance_two_scans_both_have_results(self) -> None:
        scanner = SecurityHeadersScanner()
        first = scanner.scan(self.ep())
        self.assertTrue(first)
        self.assertEqual(scanner.scan(self.ep("/other")), [])  # cùng phiên: bỏ qua
        scanner.reset()
        second = scanner.scan(self.ep())
        self.assertEqual(len(first), len(second))

    def test_origin_checked_once_within_scan(self) -> None:
        scanner = SecurityHeadersScanner()
        scanner.scan(self.ep("/a"))
        scanner.scan(self.ep("/b"))
        scanner.scan(self.ep("/c"))
        self.assertEqual(self.hits("/"), 1)

    def test_threads_do_not_check_origin_twice(self) -> None:
        scanner = SecurityHeadersScanner()
        barrier = threading.Barrier(8)
        results: list[list] = []

        def worker() -> None:
            barrier.wait()
            results.append(scanner.scan(self.ep("/t")))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for r in results if r), 1)
        self.assertEqual(self.hits("/"), 1)

    def test_engine_resets_reused_scanner_between_scans(self) -> None:
        shared = SecurityHeadersScanner()
        with mock.patch("core.engine.scan_engine.load_scanner_class", return_value=lambda **kw: shared):
            reports = [
                ScanEngine(ScanContext(target_url=self.base, max_depth=0, modules=["headers"])).run()
                for _ in range(2)
            ]
        self.assertEqual([r.status for r in reports], ["COMPLETED", "COMPLETED"])
        self.assertTrue(reports[0].findings)
        self.assertEqual(len(reports[0].findings), len(reports[1].findings))


class TestEngineNoModules(ServerCase):
    def test_all_modules_unavailable_returns_empty_structured_result(self) -> None:
        events: list[dict] = []
        ctx = ScanContext(target_url=self.base, modules=["sqli", "xss"], on_event=events.append)
        report = ScanEngine(ctx).run()
        self.assertEqual(report.status, "NO_MODULES")
        self.assertEqual(report.findings, [])
        self.assertEqual(set(report.skipped_modules), {"sqli", "xss"})
        self.assertIn("sqli", report.message)
        self.assertTrue(any(e["type"] == "warning" for e in events))
        self.assertEqual(report.to_dict()["summary"]["total_findings"], 0)
        self.assertEqual(self.hits("/"), 0)  # không crawl vô ích

    def test_partial_modules_still_run(self) -> None:
        report = ScanEngine(ScanContext(target_url=self.base, max_depth=0, modules=["sqli", "headers"])).run()
        self.assertEqual(report.status, "COMPLETED")
        self.assertEqual(report.modules, ["headers"])
        self.assertIn("sqli", report.skipped_modules)
        self.assertTrue(report.findings)

    def test_cli_no_modules_friendly_exit_code_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.json"
            code = cli_main(["-u", self.base, "-m", "sqli,xss", "-o", str(out), "--no-db", "--quiet"])
            self.assertEqual(code, 2)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "NO_MODULES")
            self.assertEqual(data["findings"], [])


if __name__ == "__main__":
    unittest.main()
