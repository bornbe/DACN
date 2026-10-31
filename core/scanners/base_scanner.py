"""
Lớp trừu tượng BaseScanner và cấu trúc Finding - Issue #3.1.
Chuẩn hóa giao diện cho mọi loại Scanner (Headers, CSRF, SQLi, XSS...), tích hợp
giới hạn tốc độ (rate limiting) và xử lý lỗi mạng mềm mại để không làm sập tiến trình quét.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import requests

from config.config import Config
from core.utils.logger import get_logger
from core.utils.payload_loader import PayloadLoader

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

logger = get_logger(__name__)

# Thứ tự độ nghiêm trọng (cao -> thấp) dùng để sắp xếp và thống kê
SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Giới hạn độ dài bằng chứng lưu trữ, tránh phình CSDL/báo cáo
MAX_EVIDENCE_LENGTH = 1000


@dataclass
class Finding:
    """Một phát hiện lỗ hổng do Scanner trả về."""

    vuln_name: str
    severity: str
    target_url: str
    parameter: str | None = None
    payload: str | None = None
    evidence: str | None = None
    cwe_id: str | None = None
    remediation: str | None = None
    owasp_category: str | None = None

    def __post_init__(self) -> None:
        self.severity = (self.severity or "INFO").upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "INFO"
        if self.evidence and len(self.evidence) > MAX_EVIDENCE_LENGTH:
            self.evidence = self.evidence[:MAX_EVIDENCE_LENGTH] + "...[truncated]"

    def dedup_key(self) -> tuple[str, str, str]:
        """Khóa nhận diện phát hiện trùng lặp: cùng loại lỗ hổng + URL + tham số."""
        return (self.vuln_name.strip().lower(), self.target_url, self.parameter or "")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseScanner(ABC):
    """
    Lớp cơ sở của mọi Scanner. Lớp con chỉ cần cài đặt `scan(endpoint)`.
    Các tiện ích dùng chung:
    - `send()`: gửi HTTP request có rate limiting, bắt lỗi mạng và trả None khi thất bại.
    - `safe_scan()`: bọc `scan()` để mọi ngoại lệ không làm gián đoạn tiến trình quét chính.
    - `make_finding()`: dựng Finding với thông tin mặc định từ danh mục OWASP.
    """

    # Khóa danh mục trong owasp_catalog.json (sqli, xss, csrf, security_headers)
    category: str = ""
    name: str = "base"

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int | None = None,
        request_delay: float = 0.0,
        user_agent: str = "OWASP-Scanner/1.0",
        stop_event: threading.Event | None = None,
        payload_loader: PayloadLoader | None = None,
    ) -> None:
        self.timeout: int = timeout if timeout is not None else Config.DEFAULT_REQUEST_TIMEOUT
        self.request_delay: float = max(0.0, request_delay)
        self.stop_event = stop_event
        self.session: requests.Session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.payload_loader = payload_loader or PayloadLoader()

        self._rate_lock = threading.Lock()
        self._last_request_at: float = 0.0
        self._catalog: dict[str, Any] | None = None

    @abstractmethod
    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        """Kiểm thử một endpoint và trả về danh sách phát hiện."""
        raise NotImplementedError

    def safe_scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        """Chạy `scan()` và nuốt mọi ngoại lệ (ghi log) để tiến trình quét chính không bị sập."""
        try:
            return self.scan(endpoint) or []
        except Exception as exc:  # noqa: BLE001 - chủ ý bắt rộng để cô lập lỗi từng scanner
            logger.warning("Scanner '%s' lỗi tại %s: %s", self.name, endpoint.url, exc)
            return []

    def _throttle(self) -> None:
        """Giới hạn tốc độ: đảm bảo khoảng cách tối thiểu `request_delay` giữa hai request."""
        if self.request_delay <= 0:
            return
        with self._rate_lock:
            wait = self.request_delay - (time.monotonic() - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
            self._last_request_at = time.monotonic()

    def send(
        self,
        method: str,
        url: str,
        session: requests.Session | None = None,
        **kwargs: Any,
    ) -> requests.Response | None:
        """Gửi HTTP request an toàn. Trả về None nếu bị hủy hoặc gặp lỗi mạng/timeout."""
        if self.stop_event is not None and self.stop_event.is_set():
            return None
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        try:
            return (session or self.session).request(method.upper(), url, **kwargs)
        except requests.RequestException as exc:
            logger.warning("Lỗi mạng khi %s %s: %s", method, url, exc)
            return None

    def _category_info(self) -> dict[str, Any]:
        if self._catalog is None:
            try:
                self._catalog = self.payload_loader.load_owasp_catalog().get("categories", {})
            except Exception as exc:  # noqa: BLE001
                logger.warning("Không nạp được danh mục OWASP: %s", exc)
                self._catalog = {}
        return self._catalog.get(self.category, {})

    def make_finding(
        self,
        vuln_name: str,
        target_url: str,
        severity: str | None = None,
        parameter: str | None = None,
        payload: str | None = None,
        evidence: str | None = None,
        cwe_id: str | None = None,
        remediation: str | None = None,
    ) -> Finding:
        """Dựng Finding, tự điền severity/CWE/OWASP/remediation mặc định từ danh mục OWASP."""
        info = self._category_info()
        return Finding(
            vuln_name=vuln_name,
            severity=severity or info.get("default_severity", "INFO"),
            target_url=target_url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            cwe_id=cwe_id or info.get("cwe_id"),
            remediation=remediation or info.get("remediation"),
            owasp_category=info.get("owasp_id"),
        )
