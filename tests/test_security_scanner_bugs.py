import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import requests

from core.crawler.form_parser import EndpointDescriptor
from core.engine.result_manager import ResultManager
from core.scanners.sqli_scanner import SQLiScanner
from core.scanners.xss_scanner import XSSScanner


def make_response(body, content_type="text/html; charset=utf-8"):
    r = requests.Response()
    r.status_code = 200
    r._content = body.encode()
    r.encoding = "utf-8"
    r.headers["Content-Type"] = content_type
    return r


class _Server:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestOutOfScopeRedirect(unittest.TestCase):
    def test_no_request_to_out_of_scope_host(self):
        hits = []

        class Out(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                body = b"You have an error in your SQL syntax; xsscanary<>\"'"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        with _Server(Out) as out:
            target = f"http://127.0.0.1:{out.port}/trap"

            class In(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(302)
                    self.send_header("Location", target)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, *a):
                    pass

            with _Server(In) as inn:
                ep = EndpointDescriptor(url=f"http://127.0.0.1:{inn.port}/p", method="GET", params={"q": "1"})
                self.assertEqual(SQLiScanner().scan(ep), [])
                self.assertEqual(XSSScanner().scan(ep), [])
        self.assertEqual(hits, [])

    def test_in_scope_redirect_followed(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
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

            def log_message(self, *a):
                pass

        with _Server(H) as s:
            r = SQLiScanner().send("GET", f"http://127.0.0.1:{s.port}/a")
            self.assertEqual(r.text, "ok")


class TestXSSReflectionClassification(unittest.TestCase):
    TOKEN = "xsstoken123"

    def run_scan(self, body, content_type="text/html"):
        scanner = XSSScanner(canary_token=self.TOKEN)
        ep = EndpointDescriptor(url="http://127.0.0.1:1/x", method="GET", params={"q": "1"})
        with patch.object(scanner, "send", return_value=make_response(body, content_type)):
            return scanner.scan(ep)

    def test_plain_text(self):
        self.assertEqual(self.run_scan(self.TOKEN + "<>\"'", "text/plain"), [])

    def test_html_escaped(self):
        self.assertEqual(self.run_scan(f"<p>{self.TOKEN}&lt;&gt;&quot;&#x27;</p>"), [])

    def test_unencoded_html_needs_review(self):
        f = self.run_scan(f"<p>{self.TOKEN}<>\"'</p>")
        self.assertEqual(len(f), 1)
        self.assertNotEqual(f[0].vuln_name, "Reflected XSS")
        self.assertIn(f[0].severity, ("LOW", "INFO"))
        self.assertIn("HTML", f[0].evidence)

    def test_unencoded_attribute(self):
        f = self.run_scan(f'<input value="{self.TOKEN}<>"\'">')
        self.assertEqual(len(f), 1)
        self.assertIn("attribute", f[0].evidence)


class TestEvidenceMasking(unittest.TestCase):
    SECRETS = ("secret_jwt_token_12345", "super_secret_cookie_67890", "my_private_api_token_abcdef")

    def body(self):
        return (
            "You have an error in your SQL syntax near x\n"
            "Authorization: Bearer secret_jwt_token_12345\n"
            "Set-Cookie: sid=super_secret_cookie_67890; HttpOnly\n"
            'token="my_private_api_token_abcdef"\n'
            "<p>xsscanary<>\"'</p>\n"
        )

    def test_masked(self):
        ep = EndpointDescriptor(url="http://127.0.0.1:1/x", method="GET", params={"q": "1"})
        sqli, xss = SQLiScanner(), XSSScanner(canary_token="xsscanary")
        with patch.object(sqli, "send", return_value=make_response(self.body())), \
                patch.object(xss, "send", return_value=make_response(self.body())):
            fs = sqli.scan(ep) + xss.scan(ep)
        rm = ResultManager()
        for f in fs:
            rm.add(f)
        out = rm.findings
        names = {f.vuln_name for f in out}
        self.assertIn("SQL Injection (Error-based)", names)
        self.assertTrue(any(n.startswith("Unencoded Input Reflection") for n in names))
        for f in out:
            self.assertEqual(f.parameter, "q")
            for s in self.SECRETS:
                self.assertNotIn(s, f.evidence)
        self.assertTrue(any("[REDACTED]" in f.evidence for f in out))


if __name__ == "__main__":
    unittest.main()
