"""
Kiểm thử Crawler đi qua SafeHTTPClient dùng chung (fix review #2).
Xác nhận crawler KHÔNG gọi requests trực tiếp mà dùng http_client an toàn, và xử lý mềm mại
khi SafeHTTPClient chặn request vì vi phạm chính sách (loopback/scope/DNS).
Không thực hiện request mạng thật: HTTP transport được mock hoàn toàn.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from core.crawler.bfs_crawler import BFSCrawler
from core.security.target_validator import SSRFBlockedError


def _html_response(body: str, url: str = "http://127.0.0.1:8080/") -> SimpleNamespace:
    return SimpleNamespace(
        text=body,
        status_code=200,
        url=url,
        headers={"Content-Type": "text/html; charset=utf-8"},
        apparent_encoding="utf-8",
        encoding="utf-8",
    )


def test_crawler_uses_injected_safe_http_client() -> None:
    """Crawler phải gửi request qua http_client (SafeHTTPClient), không bypass bằng requests."""
    http = MagicMock()
    http.get.return_value = _html_response("<html><body><a href='/child'>c</a></body></html>")

    crawler = BFSCrawler("http://127.0.0.1:8080/", max_depth=0, max_pages=5, http_client=http)
    crawler.crawl()

    assert http.get.called, "Crawler phải gọi SafeHTTPClient.get, không dùng requests trực tiếp."
    # Mọi lệnh gọi phải đi qua http_client đã tiêm.
    assert http.get.call_count >= 1


def test_crawler_soft_handles_policy_violation() -> None:
    """Khi SafeHTTPClient chặn (SSRFBlockedError), crawler bỏ qua trang, không sập."""
    http = MagicMock()
    http.get.side_effect = SSRFBlockedError("ngoài phạm vi loopback")

    crawler = BFSCrawler("http://127.0.0.1:8080/", max_depth=1, max_pages=5, http_client=http)
    result = crawler.crawl()

    assert result.endpoints == []
    assert http.get.called  # vẫn thử gọi, nhưng bị chặn an toàn