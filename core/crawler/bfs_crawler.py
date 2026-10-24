"""
Thuật toán thu thập liên kết theo chiều rộng (BFS Crawler) và kiểm soát phạm vi - Issue #2.1.
Duyệt đệ quy website mục tiêu theo cấu trúc đồ thị BFS, sử dụng hàng đợi FIFO
(collections.deque) kết hợp tập visited_urls để chống trùng lặp và vòng lặp vô hạn.
Tối ưu hiệu năng HTTP bằng requests.Session (Connection Pooling).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

import requests

from config.config import Config
from core.crawler.form_parser import EndpointDescriptor, FormParser
from core.crawler.url_parser import URLParser

# Hàm callback báo tiến độ: nhận (số trang đã quét, URL hiện tại)
ProgressCallback = Callable[[int, str], None]


@dataclass
class CrawlResult:
    """Kết quả trả về sau khi hoàn tất một phiên crawl."""

    base_url: str
    visited_urls: list[str] = field(default_factory=list)
    endpoints: list[EndpointDescriptor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "total_pages": len(self.visited_urls),
            "total_endpoints": len(self.endpoints),
            "visited_urls": self.visited_urls,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
        }


class BFSCrawler:
    """
    Bộ thu thập liên kết Web theo thuật toán Duyệt theo chiều rộng (BFS).
    Chỉ crawl trong phạm vi Hostname mục tiêu, có kiểm soát độ sâu (max_depth),
    số trang tối đa (max_pages) và thời gian chờ mỗi request (timeout).
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int | None = None,
        max_pages: int | None = None,
        timeout: int | None = None,
        session: requests.Session | None = None,
        user_agent: str = "OWASP-Scanner-Crawler/1.0",
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self.base_url: str = URLParser.normalize(base_url)
        self.max_depth: int = max_depth if max_depth is not None else Config.DEFAULT_MAX_DEPTH
        self.max_pages: int = max_pages if max_pages is not None else Config.DEFAULT_MAX_PAGES
        self.timeout: int = timeout if timeout is not None else Config.DEFAULT_REQUEST_TIMEOUT
        self.on_progress = on_progress

        # Dùng chung một Session để tái sử dụng kết nối TCP (Connection Pooling)
        self.session: requests.Session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

        self.url_parser = URLParser(self.base_url)
        self.form_parser = FormParser(self.url_parser)

        self.visited: set[str] = set()
        # 'seen' gồm mọi URL ĐÃ hoặc ĐANG nằm trong hàng đợi -> chống nạp trùng vào queue
        self.seen: set[str] = set()
        self._endpoint_signatures: set[str] = set()
        self.endpoints: list[EndpointDescriptor] = []

    def crawl(self) -> CrawlResult:
        """
        Thực thi thuật toán BFS: lần lượt lấy URL khỏi hàng đợi, tải trang,
        bóc tách endpoint và nạp các liên kết con hợp lệ vào hàng đợi.
        """
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        self.seen.add(self.base_url)

        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.popleft()

            if current_url in self.visited:
                continue
            self.visited.add(current_url)

            html = self._fetch(current_url)
            if self.on_progress:
                self.on_progress(len(self.visited), current_url)
            if html is None:
                continue

            # 1) Ghi nhận endpoint GET nếu URL hiện tại có tham số truy vấn
            self._collect_query_endpoint(current_url, depth)

            # 2) Bóc tách các form trong trang thành endpoint
            for endpoint in self.form_parser.parse_forms(html, current_url, depth):
                self._add_endpoint(endpoint)

            # 3) Mở rộng BFS: nạp các liên kết con nếu chưa vượt quá độ sâu tối đa
            if depth < self.max_depth:
                for link in self._extract_links(html, current_url):
                    if link not in self.seen:
                        self.seen.add(link)
                        queue.append((link, depth + 1))

        return CrawlResult(
            base_url=self.base_url,
            visited_urls=sorted(self.visited),
            endpoints=self.endpoints,
        )

    def _fetch(self, url: str) -> str | None:
        """
        Tải nội dung HTML của một URL. Trả về None khi gặp lỗi mạng,
        mã trạng thái không hợp lệ hoặc nội dung không phải HTML.
        Bắt ngoại lệ mềm mại để không làm sập toàn bộ tiến trình crawl.
        """
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

        if response.status_code >= 400:
            return None
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            return None
        return response.text

    def _collect_query_endpoint(self, url: str, depth: int) -> None:
        """Nếu URL chứa query string, tạo một EndpointDescriptor phương thức GET."""
        params = self.url_parser.extract_query_params(url)
        if not params:
            return
        endpoint = EndpointDescriptor(
            url=self.url_parser.strip_query(url),
            method="GET",
            params=params,
            source="query",
            depth=depth,
        )
        self._add_endpoint(endpoint)

    def _add_endpoint(self, endpoint: EndpointDescriptor) -> None:
        """Thêm endpoint vào danh sách kết quả, bỏ qua nếu đã tồn tại (lọc trùng)."""
        signature = endpoint.signature()
        if signature in self._endpoint_signatures:
            return
        self._endpoint_signatures.add(signature)
        self.endpoints.append(endpoint)

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        """
        Bóc tách toàn bộ thẻ <a href="..."> trong trang, chuyển sang URL tuyệt đối
        và lọc chỉ giữ lại các liên kết cùng phạm vi, có thể crawl được.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            absolute = self.url_parser.to_absolute(anchor["href"], current_url)
            if not absolute:
                continue
            if self.url_parser.is_in_scope(absolute) and self.url_parser.is_crawlable(absolute):
                links.append(absolute)
        return links
