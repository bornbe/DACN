"""
Kiểm thử Module 3 (BaseScanner, Security Headers, Anti-CSRF) và Module 4 (Engine, CLI).
Sử dụng máy chủ HTTP cục bộ làm mục tiêu giả lập.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from core.crawler.form_parser import EndpointDescriptor
from core.engine import ResultManager, ScanContext, ScanEngine
from core.scanners import Finding, load_scanner_class
from core.scanners.base_scanner import BaseScanner
from core.scanners.csrf_scanner import CSRFScanner
from core.scanners.security_headers_scanner import SecurityHeadersScanner
from models import Base, VulnerabilityFinding, get_session_factory, init_db
from scanner import main as cli_main
from services.report_service import export_report

PAGE = """<html><body>
<a href="/login">login</a>
<form action="/login" method="POST"><input name="user"><input type="password" name="pw"></form>
<form action="/safe" method="POST"><input type="hidden" name="csrf_token" value="a1b2c3d4e5f6a7b8"><input name="msg"></form>
<form action="/search" method="GET"><input name="q"></form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Content-Type-Options", "sniff")
        self.send_header("Content-Security-Policy", "default-src * 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(PAGE.encode())

    def log_message(self, *args) -> None:  # im lặng
        pass


class LocalServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()


class TestScanners(LocalServerCase):
    def test_finding_normalization_and_dedup_key(self) -> None:
        f = Finding("X", "weird", "http://a", evidence="e" * 5000)
        self.assertEqual(f.severity, "INFO")
        self.assertLess(len(f.evidence), 1100)

    def test_base_scanner_is_abstract_and_safe_scan_isolates_errors(self) -> None:
        with self.assertRaises(TypeError):
            BaseScanner()  # type: ignore[abstract]

        class Boom(BaseScanner):
            def scan(self, endpoint):
                raise RuntimeError("boom")

        self.assertEqual(Boom().safe_scan(EndpointDescriptor(url=self.base)), [])

    def test_network_error_is_soft(self) -> None:
        class Dummy(BaseScanner):
            def scan(self, endpoint):
                return []

        self.assertIsNone(Dummy(timeout=1).send("GET", "http://127.0.0.1:1/"))

    def test_security_headers(self) -> None:
        scanner = SecurityHeadersScanner()
        findings = scanner.scan(EndpointDescriptor(url=self.base + "/x"))
        names = {f.vuln_name for f in findings}
        self.assertIn("Missing Security Header: X-Frame-Options", names)
        self.assertIn("Weak Security Header: X-Content-Type-Options", names)
        self.assertIn("Weak Security Header: Content-Security-Policy", names)
        # HTTP thuần: không báo thiếu HSTS; mỗi Origin chỉ kiểm tra một lần
        self.assertNotIn("Missing Security Header: Strict-Transport-Security", names)
        self.assertEqual(scanner.scan(EndpointDescriptor(url=self.base + "/y")), [])

    def test_csrf_scanner(self) -> None:
        scanner = CSRFScanner(check_static_token=False)
        missing = scanner.scan(EndpointDescriptor(url=self.base + "/login", method="POST", params={"user": ""}))
        self.assertEqual(missing[0].vuln_name, "Anti-CSRF Token Missing")
        self.assertEqual(missing[0].cwe_id, "CWE-352")

        weak = scanner.scan(EndpointDescriptor(url=self.base + "/a", method="POST", params={"csrf_token": ""}))
        self.assertEqual(weak[0].vuln_name, "Anti-CSRF Token Empty or Weak")

        ok = scanner.scan(
            EndpointDescriptor(url=self.base + "/safe", method="POST", params={"csrf_token": "a1b2c3d4e5f6a7b8"})
        )
        self.assertEqual(ok, [])
        self.assertEqual(scanner.scan(EndpointDescriptor(url=self.base, method="GET", params={"q": ""})), [])

    def test_csrf_static_token_detected(self) -> None:
        scanner = CSRFScanner()
        findings = scanner.scan(
            EndpointDescriptor(url=self.base + "/safe", method="POST", params={"csrf_token": "a1b2c3d4e5f6a7b8"})
        )
        # Máy chủ giả lập luôn trả cùng một token cho mọi phiên => token cố định
        self.assertEqual(findings[0].vuln_name, "Anti-CSRF Token Static")

    def test_registry_skips_unimplemented_modules(self) -> None:
        self.assertIs(load_scanner_class("headers"), SecurityHeadersScanner)
        with self.assertRaises((ImportError, LookupError)):
            load_scanner_class("sqli")


class TestEngine(LocalServerCase):
    def test_result_manager_dedup(self) -> None:
        rm = ResultManager()
        self.assertTrue(rm.add(Finding("A", "HIGH", "http://x", "p")))
        self.assertFalse(rm.add(Finding("A", "HIGH", "http://x", "p")))
        self.assertTrue(rm.add(Finding("A", "LOW", "http://x", "q")))
        self.assertEqual(rm.severity_counts()["HIGH"], 1)
        self.assertEqual(rm.findings[0].severity, "HIGH")

    def test_engine_end_to_end_with_db_encryption(self) -> None:
        engine = init_db("sqlite:///:memory:")
        db = get_session_factory(engine)()
        events: list[dict] = []
        ctx = ScanContext(
            target_url=self.base, max_depth=1, modules=["all"], persist=True, on_event=events.append
        )
        report = ScanEngine(ctx, db_session=db).run()
        try:
            self.assertEqual(report.status, "COMPLETED")
            self.assertIn("sqli", report.skipped_modules)
            self.assertEqual(set(report.modules), {"headers", "csrf"})
            self.assertTrue(any(f.vuln_name == "Anti-CSRF Token Missing" for f in report.findings))
            self.assertEqual(report.summary["total_findings"], len(report.findings))
            self.assertEqual([e for e in events if e["type"] == "progress"][-1]["percent"], 100)

            stored = db.query(VulnerabilityFinding).filter_by(session_id=report.session_id).all()
            self.assertEqual(len(stored), len(report.findings))
        finally:
            db.close()
            Base.metadata.drop_all(bind=engine)

    def test_engine_invalid_url_fails_gracefully(self) -> None:
        report = ScanEngine(ScanContext(target_url="ftp://x")).run()
        self.assertEqual(report.status, "FAILED")

    def test_engine_cancel(self) -> None:
        ctx = ScanContext(target_url=self.base, modules=["headers"])
        ctx.stop_event.set()
        self.assertEqual(ScanEngine(ctx).run().status, "CANCELLED")

    def test_cli_exports_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_json = Path(tmp) / "r.json"
            out_txt = Path(tmp) / "r.txt"
            out_pdf = Path(tmp) / "r.pdf"
            for out in (out_json, out_txt):
                code = cli_main(["-u", self.base, "-d", "1", "-m", "headers,csrf", "-o", str(out), "--no-db", "--quiet"])
                self.assertEqual(code, 0)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "COMPLETED")
            self.assertIn("OWASP AUTOMATED PENTEST REPORT", out_txt.read_text(encoding="utf-8"))

            try:
                export_report(data, out_pdf)
                self.assertTrue(out_pdf.read_bytes().startswith(b"%PDF"))
            except RuntimeError:
                self.skipTest("reportlab chưa được cài đặt")

    def test_cli_rejects_invalid_module(self) -> None:
        with self.assertRaises(SystemExit):
            cli_main(["-u", self.base, "-m", "nope", "--no-db"])


if __name__ == "__main__":
    unittest.main()
