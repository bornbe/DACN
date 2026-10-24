"""
Tiện ích phân tích, chuẩn hóa URL và kiểm soát phạm vi quét (Scope Filter) - Issue #2.1.
Cung cấp các hàm tách liên kết, chuyển liên kết tương đối sang tuyệt đối,
kiểm tra liên kết có cùng Hostname/Domain mục tiêu hay không và bóc tách
tham số truy vấn (query parameters) từ URL.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse


class URLParser:
    """
    Bộ phân tích URL phục vụ cho BFS Crawler.
    Mỗi lần quét một mục tiêu sẽ khởi tạo một URLParser gắn với Hostname gốc,
    dùng để lọc phạm vi (chỉ crawl trong cùng domain) và chống trùng lặp.
    """

    # Các đuôi tệp tĩnh (ảnh, style, script, tài liệu...) sẽ bị bỏ qua khi crawl
    SKIP_EXTENSIONS: frozenset[str] = frozenset(
        {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
            ".pdf", ".zip", ".rar", ".gz", ".tar", ".7z",
            ".mp3", ".mp4", ".avi", ".mov", ".webm", ".wav",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        }
    )

    # Chỉ chấp nhận hai giao thức HTTP/HTTPS
    ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

    def __init__(self, base_url: str) -> None:
        normalized = self.normalize(base_url)
        parsed = urlparse(normalized)
        self.base_url: str = normalized
        self.base_scheme: str = parsed.scheme or "http"
        # Dùng hostname (bỏ cổng :port và thông tin user) thay cho netloc để so khớp chính xác
        self.base_host: str = (parsed.hostname or "").lower()

    @staticmethod
    def normalize(url: str) -> str:
        """
        Chuẩn hóa URL để chống trùng lặp:
        - Loại bỏ phần fragment (#section).
        - Bỏ dấu '/' thừa ở cuối đường dẫn (trừ đường dẫn gốc).
        """
        url, _fragment = urldefrag(url.strip())
        parsed = urlparse(url)
        path = parsed.path
        if not path:
            # Chuẩn hóa trang gốc: '.../local' và '.../local/' xem như một
            path = "/"
        elif len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        parsed = parsed._replace(path=path)
        return parsed.geturl()

    def to_absolute(self, link: str, current_url: str) -> str | None:
        """
        Chuyển một liên kết (có thể tương đối) thành URL tuyệt đối dựa trên trang hiện tại.
        Trả về None nếu liên kết không hợp lệ (javascript:, mailto:, tel:, rỗng...).
        """
        link = link.strip()
        if not link:
            return None
        lowered = link.lower()
        if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None

        absolute = urljoin(current_url, link)
        absolute = self.normalize(absolute)
        parsed = urlparse(absolute)
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            return None
        return absolute

    def is_in_scope(self, url: str) -> bool:
        """
        Kiểm tra URL có nằm trong phạm vi (cùng Hostname với mục tiêu) hay không.
        Chấp nhận khác biệt ở tiền tố 'www.' (vd: example.com và www.example.com).
        """
        parsed = urlparse(url)
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        return host == self.base_host or host.removeprefix("www.") == self.base_host.removeprefix("www.")

    def is_crawlable(self, url: str) -> bool:
        """Loại bỏ các liên kết trỏ tới tài nguyên tĩnh (ảnh, css, js, tài liệu...)."""
        path = urlparse(url).path.lower()
        return not any(path.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    @staticmethod
    def extract_query_params(url: str) -> dict[str, str]:
        """
        Bóc tách các tham số truy vấn (query string) từ URL.
        Ví dụ: 'http://site/page?id=1&cat=2' -> {'id': '1', 'cat': '2'}.
        """
        query = urlparse(url).query
        return {key: value for key, value in parse_qsl(query, keep_blank_values=True)}

    @staticmethod
    def strip_query(url: str) -> str:
        """Trả về URL đã loại bỏ phần query string (giữ lại scheme://host/path)."""
        parsed = urlparse(url)
        return parsed._replace(query="", fragment="").geturl()
