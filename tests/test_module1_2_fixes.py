"""
Kiểm thử Module 1 (mã hóa At-Rest, xử lý khóa, ORM/DB) và Module 2 (Scope Filter, BFS Crawler, Form Parser).
"""

from __future__ import annotations

import hashlib
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from sqlalchemy import text

from config.config import Config
from config.crypto_utils import DEV_FALLBACK_KEY, EncryptedText, EncryptionKeyError, EncryptionService
from core.crawler import BFSCrawler, FormParser, URLParser
from core.crawler.form_parser import EndpointDescriptor
from models import (
    Base,
    CrawledEndpoint,
    ScanSession,
    ScanTarget,
    VulnerabilityFinding,
    get_engine,
    get_session_factory,
    init_db,
)


# ---------------------------------------------------------------------- Module 1
class TestKeyHandling(unittest.TestCase):
    def _service_with_blank_sources(self, **config_patch):
        with mock.patch.dict(os.environ, {"ENCRYPTION_MASTER_KEY": ""}), \
                mock.patch.object(Config, "ENCRYPTION_MASTER_KEY", ""):
            with mock.patch.multiple(Config, **config_patch) if config_patch else mock.patch.object(Config, "APP_ENV", Config.APP_ENV):
                return EncryptionService()

    def test_blank_key_falls_back_in_development(self) -> None:
        with mock.patch.object(Config, "APP_ENV", "development"):
            service = self._service_with_blank_sources()
        self.assertEqual(service.decrypt(service.encrypt("x")), "x")

    def test_blank_explicit_key_does_not_crash(self) -> None:
        with mock.patch.object(Config, "APP_ENV", "development"):
            service = EncryptionService(master_key="   ")
        self.assertEqual(service.decrypt(service.encrypt("ok")), "ok")

    def test_blank_key_in_production_raises_clear_error(self) -> None:
        with self.assertRaises(EncryptionKeyError):
            self._service_with_blank_sources(APP_ENV="production")

    def test_public_dev_key_rejected_in_production(self) -> None:
        with mock.patch.object(Config, "APP_ENV", "production"):
            with self.assertRaises(EncryptionKeyError):
                EncryptionService(master_key=DEV_FALLBACK_KEY)
            service = EncryptionService(master_key=EncryptionService.generate_master_key())
        self.assertEqual(service.decrypt(service.encrypt("p")), "p")

    def test_invalid_key_type_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            EncryptionService(master_key=12345)  # type: ignore[arg-type]

    def test_non_standard_key_is_derived_not_crash(self) -> None:
        service = EncryptionService(master_key="not-base64-and-short")
        self.assertEqual(service.decrypt(service.encrypt("v")), "v")

    def test_deterministic_vs_random_encryption(self) -> None:
        service = EncryptionService(master_key=EncryptionService.generate_master_key())
        self.assertEqual(service.encrypt("a", deterministic=True), service.encrypt("a", deterministic=True))
        self.assertNotEqual(service.encrypt("a"), service.encrypt("a"))
        self.assertEqual(service.decrypt(service.encrypt("a", deterministic=True)), "a")
        self.assertNotEqual(service.encrypt("a", deterministic=True), service.encrypt("b", deterministic=True))

    def test_encrypted_text_type_with_custom_key(self) -> None:
        col = EncryptedText(master_key=EncryptionService.generate_master_key(), deterministic=True)
        bound = col.process_bind_param("http://x", None)
        self.assertNotIn("http://x", bound)
        self.assertEqual(col.process_result_value(bound, None), "http://x")
        self.assertIsNone(col.process_bind_param(None, None))


class TestAtRestStorage(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = init_db("sqlite:///:memory:")
        self.db = get_session_factory(self.engine)()

    def tearDown(self) -> None:
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def raw(self, sql: str, **params):
        return self.db.execute(text(sql), params).fetchone()

    def test_scan_target_url_encrypted_but_still_queryable(self) -> None:
        url = "http://internal.corp.local:8080/"
        target = ScanTarget(name="t", url=url)
        self.db.add(target)
        self.db.commit()

        (raw_url,) = self.raw("SELECT url FROM scan_targets WHERE id = :i", i=target.id)
        self.assertNotIn("internal.corp.local", raw_url)
        self.assertEqual(self.db.get(ScanTarget, target.id).url, url)
        found = self.db.query(ScanTarget).filter(ScanTarget.url == url).first()
        self.assertEqual(found.id, target.id)

    def test_endpoint_params_and_error_message_encrypted(self) -> None:
        target = ScanTarget(name="t", url="http://a")
        self.db.add(target)
        self.db.flush()
        session = ScanSession(target_id=target.id, error_message="connect http://secret.internal failed")
        self.db.add(session)
        self.db.flush()
        ep = CrawledEndpoint(
            session_id=session.id, url="http://a/x", params_schema={"csrf_token": "SuperSecretValue123"}
        )
        self.db.add(ep)
        self.db.commit()

        (raw_params,) = self.raw("SELECT params_schema FROM crawled_endpoints WHERE id = :i", i=ep.id)
        (raw_err,) = self.raw("SELECT error_message FROM scan_sessions WHERE id = :i", i=session.id)
        (raw_ep_url,) = self.raw("SELECT url FROM crawled_endpoints WHERE id = :i", i=ep.id)
        self.assertNotIn("SuperSecretValue123", raw_params)
        self.assertNotIn("secret.internal", raw_err)
        self.assertNotIn("http://a/x", raw_ep_url)
        self.assertEqual(self.db.get(CrawledEndpoint, ep.id).params_schema, {"csrf_token": "SuperSecretValue123"})
        self.assertIn("secret.internal", self.db.get(ScanSession, session.id).error_message)

    def test_fingerprint_is_keyed_hmac_not_plain_sha256(self) -> None:
        args = dict(session_id=1, vuln_type="XSS", target_url="http://a/x", param="q")
        fp = VulnerabilityFinding.compute_fingerprint(**args)
        plain = hashlib.sha256(b"1|XSS|http://a/x|q").hexdigest()
        self.assertEqual(len(fp), 64)
        self.assertNotEqual(fp, plain)
        self.assertEqual(fp, VulnerabilityFinding.compute_fingerprint(**args))


class TestEngineFactory(unittest.TestCase):
    def test_same_uri_reuses_engine_and_memory_db_shared_across_threads(self) -> None:
        engine = init_db("sqlite:///:memory:")
        self.assertIs(get_engine("sqlite:///:memory:"), engine)
        factory = get_session_factory(engine)
        db = factory()
        db.add(ScanTarget(name="t", url="http://a"))
        db.commit()

        seen: list[int] = []

        def worker() -> None:
            s = factory()
            seen.append(s.query(ScanTarget).count())
            s.close()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        db.close()
        Base.metadata.drop_all(bind=engine)
        self.assertEqual(seen, [1])


# ---------------------------------------------------------------------- Module 2: URL / scope
class TestURLParser(unittest.TestCase):
    def test_normalize_dedupes_case_port_fragment(self) -> None:
        n = URLParser.normalize
        self.assertEqual(n("HTTP://Example.COM:80/a/#frag"), "http://example.com/a")
        self.assertEqual(n("https://example.com:443"), "https://example.com/")
        self.assertEqual(n("http://example.com:8080/x/"), "http://example.com:8080/x")
        self.assertEqual(n("http://example.com/a?x=1"), "http://example.com/a?x=1")

    def test_scope_same_host_subdomain_and_exclusions(self) -> None:
        p = URLParser("http://www.example.com/")
        self.assertTrue(p.is_in_scope("http://www.example.com/a"))
        self.assertTrue(p.is_in_scope("http://EXAMPLE.com/a"))
        self.assertTrue(p.is_in_scope("http://api.example.com/a"))
        self.assertTrue(p.is_in_scope("https://www.example.com/a"))  # nâng cấp HTTPS
        self.assertFalse(p.is_in_scope("http://evil-example.com/"))
        self.assertFalse(p.is_in_scope("http://example.com.evil.com/"))
        self.assertFalse(p.is_in_scope("http://www.example.com:8080/"))
        self.assertFalse(p.is_in_scope("ftp://www.example.com/"))

    def test_scope_ip_and_localhost_exact_only(self) -> None:
        p = URLParser("http://127.0.0.1:8080/")
        self.assertTrue(p.is_in_scope("http://127.0.0.1:8080/x"))
        self.assertFalse(p.is_in_scope("http://127.0.0.1:9090/x"))
        self.assertFalse(p.is_in_scope("http://localhost:8080/x"))
        self.assertFalse(URLParser("http://localhost/").is_in_scope("http://a.localhost/"))

    def test_malformed_links_do_not_raise(self) -> None:
        p = URLParser("http://example.com/")
        self.assertIsNone(p.to_absolute("http://[invalid", "http://example.com/"))
        self.assertFalse(p.is_in_scope("http://[invalid"))
        self.assertIsNone(p.to_absolute("javascript:void(0)", "http://example.com/"))
        self.assertIsNone(p.to_absolute("ftp://example.com/x", "http://example.com/"))

    def test_static_resources_skipped(self) -> None:
        p = URLParser("http://example.com/")
        for path in ("/a.png", "/a.JS", "/f.pdf", "/app.js.map"):
            self.assertFalse(p.is_crawlable("http://example.com" + path))
        self.assertTrue(p.is_crawlable("http://example.com/page?file=a.png"))


# ---------------------------------------------------------------------- Module 2: forms
class TestFormParser(unittest.TestCase):
    def parse(self, html: str, page: str = "http://example.com/dir/page") -> list[EndpointDescriptor]:
        return FormParser(URLParser("http://example.com/")).parse_forms(html, page)

    def test_hidden_fields_and_method_override(self) -> None:
        eps = self.parse(
            '<form action="/del" method="post"><input type="HIDDEN" name="_method" value="DELETE">'
            '<input type="hidden" name="id" value="7"><input name="q"><input type="submit" name="go"></form>'
        )
        ep = eps[0]
        self.assertEqual(ep.method, "POST")
        self.assertEqual(ep.params, {"_method": "DELETE", "id": "7", "q": ""})
        self.assertEqual(ep.method_override, "DELETE")
        self.assertEqual(ep.effective_method, "DELETE")
        self.assertEqual(ep.url, "http://example.com/del")

    def test_override_ignored_for_get_and_unknown_values(self) -> None:
        get_ep = self.parse('<form method="get"><input type="hidden" name="_method" value="DELETE"></form>')[0]
        self.assertIsNone(get_ep.method_override)
        weird = self.parse('<form method="post"><input type="hidden" name="_method" value="FOO"></form>')[0]
        self.assertIsNone(weird.method_override)

    def test_blank_action_invalid_method_and_external_inputs(self) -> None:
        eps = self.parse(
            '<form action="  " method="dialog" id="f1"><textarea name="t"> hi </textarea>'
            '<select name="s"><option>One</option><option value="2" selected>Two</option></select>'
            '<select name="s2"><option>Only text</option></select>'
            '<input type="checkbox" name="c"></form><input type="hidden" name="ext" value="9" form="f1">'
        )
        ep = eps[0]
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.url, "http://example.com/dir/page")
        self.assertEqual(ep.params["t"], "hi")
        self.assertEqual(ep.params["s"], "2")
        self.assertEqual(ep.params["s2"], "Only text")
        self.assertEqual(ep.params["c"], "on")
        self.assertEqual(ep.params["ext"], "9")

    def test_out_of_scope_action_skipped(self) -> None:
        self.assertEqual(self.parse('<form action="http://evil.com/x" method="post"></form>'), [])

    def test_relative_action_uses_real_page_url(self) -> None:
        ep = self.parse('<form action="save" method="post"></form>', "http://example.com/blog/")[0]
        self.assertEqual(ep.url, "http://example.com/blog/save")


# ---------------------------------------------------------------------- Module 2: crawler
class CrawlHandler(BaseHTTPRequestHandler):
    hits: list[str] = []
    lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        with self.lock:
            self.hits.append(self.path)
        port = self.server.server_port
        html = "text/html; charset=utf-8"
        routes = {
            "/": (200, [("Content-Type", html)], (
                '<a href="/blog/">b</a><a href="/api?id=1">a</a><a href="/err?id=2">e</a>'
                '<a href="http://[bad">x</a><a href="/redir-out">r</a><a href="/redir-in">r</a>'
                '<a href="/xhtml">x</a><a href="/noct">n</a><a href="/static.png">s</a>'
                f'<a href="http://localhost:{port}/leak">l</a><a href="mailto:a@b.c">m</a>'
            )),
            "/blog/": (200, [("Content-Type", html)],
                       '<a href="post1">p</a><form action="save" method="POST"><input type="hidden" name="_method" value="PUT"></form>'),
            "/blog/post1": (200, [("Content-Type", html)], "<html><body>post</body></html>"),
            "/api?id=1": (200, [("Content-Type", "application/json")], '{"a": 1}'),
            "/err?id=2": (500, [("Content-Type", html)], "boom"),
            "/redir-out": (302, [("Location", f"http://localhost:{port}/leak")], ""),
            "/redir-in": (302, [("Location", "/landing/")], ""),
            "/landing/": (200, [("Content-Type", html)], '<a href="child">c</a>'),
            "/landing/child": (200, [("Content-Type", html)], "<html></html>"),
            "/xhtml": (200, [("Content-Type", "application/xhtml+xml; charset=utf-8")], '<a href="/from-xhtml">x</a>'),
            "/from-xhtml": (200, [("Content-Type", html)], "<html></html>"),
            "/noct": (200, [], '<html><body><a href="/from-noct">n</a></body></html>'),
            "/from-noct": (200, [("Content-Type", html)], "<html></html>"),
        }
        p = self.path
        if p not in routes:
            if (p + "/") in routes:
                p = p + "/"
            elif p.rstrip("/") in routes:
                p = p.rstrip("/")
        status, headers, body = routes.get(p, (404, [], ""))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args) -> None:
        pass


class TestBFSCrawler(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CrawlHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        CrawlHandler.hits.clear()
        cls.result = BFSCrawler(cls.base, max_depth=3, max_pages=50, timeout=5).crawl()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def visited(self, path: str) -> bool:
        return self.base + path in self.result.visited_urls

    def test_relative_links_resolved_against_real_page_url(self) -> None:
        self.assertTrue(self.visited("/blog/post1"))
        self.assertTrue(self.visited("/landing/child"))

    def test_xhtml_and_missing_content_type_are_crawled(self) -> None:
        self.assertTrue(self.visited("/from-xhtml"))
        self.assertTrue(self.visited("/from-noct"))

    def test_out_of_scope_redirect_not_followed(self) -> None:
        self.assertNotIn("/leak", CrawlHandler.hits)

    def test_static_and_malformed_links_skipped(self) -> None:
        self.assertFalse(self.visited("/static.png"))
        self.assertNotIn("/static.png", CrawlHandler.hits)

    def test_query_endpoints_kept_even_for_non_html_or_error_pages(self) -> None:
        sigs = {(e.method, e.url, tuple(e.params)) for e in self.result.endpoints}
        self.assertIn(("GET", self.base + "/api", ("id",)), sigs)
        self.assertIn(("GET", self.base + "/err", ("id",)), sigs)

    def test_form_endpoint_with_method_override(self) -> None:
        forms = [e for e in self.result.endpoints if e.source == "form"]
        self.assertEqual(forms[0].url, self.base + "/blog/save")
        self.assertEqual(forms[0].effective_method, "PUT")

    def test_limits_and_no_duplicate_visits(self) -> None:
        limited = BFSCrawler(self.base, max_depth=0, max_pages=50, timeout=5).crawl()
        self.assertEqual(limited.visited_urls, [self.base + "/"])
        capped = BFSCrawler(self.base, max_depth=3, max_pages=2, timeout=5).crawl()
        self.assertLessEqual(len(capped.visited_urls), 3)
        self.assertEqual(len(self.result.visited_urls), len(set(self.result.visited_urls)))

    def test_network_error_is_soft(self) -> None:
        result = BFSCrawler("http://127.0.0.1:1/", max_depth=1, timeout=1).crawl()
        self.assertEqual(result.endpoints, [])


if __name__ == "__main__":
    unittest.main()
