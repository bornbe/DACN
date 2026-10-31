"""
Tiện ích phân tích, chuẩn hóa URL và kiểm soát phạm vi quét (Scope Filter) - Issue #2.1.
Cung cấp các hàm tách liên kết, chuyển liên kết tương đối sang tuyệt đối,
kiểm tra liên kết có cùng Hostname/Domain mục tiêu hay không và bóc tách
tham số truy vấn (query parameters) từ URL.
"""

from __future__ import annotations

import ipaddress
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
            ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
            ".pdf", ".zip", ".rar", ".gz", ".tar", ".7z",
            ".mp3", ".mp4", ".avi", ".mov", ".webm", ".wav",
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
            ".exe", ".msi", ".iso", ".apk", ".dmg",
        }
    )

    # Chỉ chấp nhận hai giao thức HTTP/HTTPS
    ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

    DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

    def __init__(self, base_url: str) -> None:
        normalized = self.normalize(base_url)
        parsed = urlparse(normalized)
        self.base_url: str = normalized
        self.base_scheme: str = parsed.scheme or "http"
        self.base_host: str = parsed.netloc.lower()
        self.base_hostname: str = (parsed.hostname or "").lower().rstrip(".")
        self.base_port: int | None = self._effective_port(parsed)
        # Miền gốc để so khớp subdomain: bỏ tiền tố 'www.'; IP/localhost chỉ khớp chính xác
        self.base_domain: str = self.base_hostname
        if self.base_domain.startswith("www."):
            self.base_domain = self.base_domain[4:]
        self._allow_subdomains: bool = "." in self.base_domain and not self._is_ip(self.base_domain)

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @classmethod
    def _effective_port(cls, parsed) -> int | None:
        """Cổng thực tế của URL (cổng mặc định theo scheme nếu không ghi rõ)."""
        try:
            port = parsed.port
        except ValueError:
            return None
        return port if port is not None else cls.DEFAULT_PORTS.get(parsed.scheme)

    @classmethod
    def normalize(cls, url: str) -> str:
        """
        Chuẩn hóa URL để chống trùng lặp:
        - Loại bỏ phần fragment (#section).
        - Scheme và hostname về chữ thường; bỏ cổng mặc định (:80 cho http, :443 cho https).
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

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        if parsed.hostname:
            userinfo = netloc.rpartition("@")[0]
            host = parsed.hostname.lower()
            if ":" in host:  # IPv6 literal
                host = f"[{host}]"
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError(f"URL có cổng không hợp lệ: {url}") from exc
            if port is not None and port == cls.DEFAULT_PORTS.get(scheme):
                port = None
            netloc = (f"{userinfo}@" if userinfo else "") + host + (f":{port}" if port is not None else "")
        parsed = parsed._replace(scheme=scheme, netloc=netloc, path=path)
        return parsed.geturl()

    def to_absolute(self, link: str, current_url: str) -> str | None:
        """
        Chuyển một liên kết (có thể tương đối) thành URL tuyệt đối dựa trên trang hiện tại.
        Trả về None nếu liên kết không hợp lệ (javascript:, mailto:, tel:, rỗng, URL dị dạng...).
        """
        link = (link or "").strip()
        if not link:
            return None
        lowered = link.lower()
        if lowered.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None

        try:
            parsed_cur = urlparse(current_url)
            base_path = parsed_cur.path or "/"
            base = parsed_cur._replace(path=base_path, query="", fragment="").geturl()
            last_seg = parsed_cur.path.rstrip("/").split("/")[-1] if parsed_cur.path else ""
            if last_seg and "." not in last_seg and not base_path.endswith("/"):
                base = parsed_cur._replace(path=f"{base_path}/", query="", fragment="").geturl()
            absolute = urljoin(base, link)
            absolute = self.normalize(absolute)
            parsed = urlparse(absolute)
        except ValueError:
            # Ví dụ href="http://[invalid" làm urlparse ném ValueError: bỏ qua liên kết thay vì sập crawler
            return None
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            return None
        return absolute

    def is_in_scope(self, url: str) -> bool:
        """
        Kiểm tra URL có nằm trong phạm vi hay không: cùng Hostname (hoặc subdomain của miền mục tiêu)
        và cùng cổng (http/https cổng mặc định được coi là tương đương để theo kịp chuyển hướng HTTP->HTTPS).
        """
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = self._effective_port(parsed)
        except ValueError:
            return False
        if parsed.scheme not in self.ALLOWED_SCHEMES or not hostname:
            return False

        host_ok = hostname == self.base_hostname or (
            self._allow_subdomains
            and (hostname == self.base_domain or hostname.endswith("." + self.base_domain))
        )
        if not host_ok:
            return False

        default_ports = set(self.DEFAULT_PORTS.values())
        return port == self.base_port or (port in default_ports and self.base_port in default_ports)

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
