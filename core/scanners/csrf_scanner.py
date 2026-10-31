"""
Module phát hiện Anti-CSRF Token Missing - Issue #3.3.
Lọc các form thay đổi trạng thái (POST/PUT/DELETE, kể cả method override qua `_method`),
tìm token CSRF từ nhiều nguồn: tham số endpoint, <input type="hidden"> trong form HTML và
<meta name="csrf-token">. Ghi nhận cơ chế thay thế (cookie XSRF-TOKEN/csrftoken, header
X-CSRF-Token/X-XSRF-TOKEN, cookie SameSite=Lax/Strict) để tránh báo "Missing" sai.
Gắn nhãn lỗ hổng khi form không có token ở bất kỳ nguồn nào, token rỗng/yếu hoặc token cố định.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from core.crawler.url_parser import URLParser
from core.scanners.base_scanner import BaseScanner, Finding
from core.utils.logger import get_logger

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

logger = get_logger(__name__)

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Pattern tên trường nghi là token CSRF (không phân biệt hoa/thường)
TOKEN_NAME_PATTERN = re.compile(
    r"csrf|xsrf|authenticity_token|requestverificationtoken|anti-?forgery|_token|nonce|^token$",
    re.I,
)

# Tên thẻ <meta> chứa token CSRF (ví dụ <meta name="csrf-token">)
META_NAME_PATTERN = re.compile(r"csrf|xsrf", re.I)

# Header phản hồi/cookie cho thấy cơ chế chống CSRF thay thế (double-submit, token qua header)
ALT_HEADER_NAMES = frozenset({"x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token", "x-csrftoken"})
CSRF_COOKIE_PATTERN = re.compile(r"csrf|xsrf", re.I)
SAMESITE_PATTERN = re.compile(r"samesite\s*=\s*(lax|strict)", re.I)

# Giá trị giữ chỗ không phải token thật
PLACEHOLDER_VALUES = frozenset({"", "token", "null", "none", "undefined", "csrf", "test", "0", "1", "true", "false"})
MIN_TOKEN_LENGTH = 8
# Entropy Shannon tối thiểu (bit/ký tự) của token hợp lý
MIN_TOKEN_ENTROPY = 2.0


@dataclass
class _TokenCandidate:
    name: str
    value: str
    source: str  # "param" | "input" | "meta"


@dataclass
class _Alternatives:
    """Các cơ chế chống CSRF thay thế phát hiện được từ phản hồi của trang."""

    strong: list[str]  # cookie CSRF, header CSRF
    samesite: list[str]  # cookie SameSite=Lax/Strict

    def describe(self) -> str:
        return "; ".join([*self.strong, *self.samesite])


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


def is_weak_token(value: str | None) -> bool:
    """Token rỗng, giữ chỗ, quá ngắn hoặc có entropy quá thấp (ví dụ 'aaaaaaaa')."""
    token = (value or "").strip()
    if token.lower() in PLACEHOLDER_VALUES or len(token) < MIN_TOKEN_LENGTH:
        return True
    return _shannon_entropy(token) < MIN_TOKEN_ENTROPY


class CSRFScanner(BaseScanner):
    """Rà soát form POST/PUT/DELETE thiếu cơ chế chống giả mạo yêu cầu chéo trang."""

    category = "csrf"
    name = "csrf"

    def __init__(self, *args: Any, check_static_token: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.check_static_token = check_static_token
        self._token_names: set[str] = set()
        try:
            names = self._category_info().get("recognized_token_names", [])
            self._token_names = {n.lower() for n in names}
        except Exception:  # noqa: BLE001
            self._token_names = set()
        self._seen_forms: set[str] = set()
        # Cache theo trang: mỗi trang chỉ GET một lần trong một phiên quét
        self._pages: dict[str, tuple[requests.Response | None, BeautifulSoup | None]] = {}

    def reset(self) -> None:
        """Bắt đầu phiên quét mới: xóa form đã xét và cache trang."""
        self._seen_forms.clear()
        self._pages.clear()

    # ------------------------------------------------------------------ main
    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        method = self._effective_method(endpoint.method, endpoint.params)
        if method not in STATE_CHANGING_METHODS:
            return []

        signature = endpoint.signature()
        if signature in self._seen_forms:
            return []
        self._seen_forms.add(signature)

        page_url = getattr(endpoint, "page_url", None) or endpoint.url
        response, soup = self._get_page(page_url)
        form = self._find_form(soup, endpoint, page_url) if soup is not None else None
        if form is not None:
            method = self._form_method(form) or method

        candidates = self._collect_tokens(endpoint.params, form, soup)
        field_list = ", ".join(endpoint.params) or "(không có trường)"
        note = "" if soup is not None else " (không xác minh được HTML của trang)"

        strong = [c for c in candidates if not is_weak_token(c.value)]
        if strong:
            best = strong[0]
            if (
                self.check_static_token
                and best.source != "meta"
                and self._is_static_token(page_url, best.name)
            ):
                return [
                    self.make_finding(
                        vuln_name="Anti-CSRF Token Static",
                        target_url=endpoint.url,
                        parameter=best.name,
                        evidence=(
                            f"Trường '{best.name}' có cùng giá trị ở hai phiên truy cập độc lập, "
                            "cho thấy token cố định thay vì gắn với phiên làm việc."
                        ),
                    )
                ]
            return []

        alt = self._detect_alternatives(response)

        if candidates:
            weak = candidates[0]
            severity = "LOW" if alt.strong else None
            extra = f" Cơ chế thay thế: {alt.describe()}." if alt.strong else ""
            return [
                self.make_finding(
                    vuln_name="Anti-CSRF Token Empty or Weak",
                    target_url=endpoint.url,
                    severity=severity,
                    parameter=weak.name,
                    evidence=(
                        f"Trường '{weak.name}' ({weak.source}) có giá trị rỗng/giữ chỗ/quá ngắn/entropy thấp: "
                        f"'{weak.value}'.{extra}"
                    ),
                )
            ]

        # Không có token ở form/params/meta: xét cơ chế thay thế
        if alt.strong:
            return []
        if alt.samesite:
            return [
                self.make_finding(
                    vuln_name="Anti-CSRF Token Not Found (Mitigated by SameSite Cookie)",
                    target_url=endpoint.url,
                    severity="INFO",
                    evidence=(
                        f"Form {method} tới {endpoint.url} không có token CSRF nhưng cookie đặt "
                        f"SameSite ({alt.describe()}) giảm thiểu rủi ro. Nên bổ sung token CSRF."
                    ),
                )
            ]
        return [
            self.make_finding(
                vuln_name="Anti-CSRF Token Missing",
                target_url=endpoint.url,
                evidence=(
                    f"Form {method} tới {endpoint.url} không chứa token CSRF trong tham số, "
                    f"hidden input, thẻ meta, cookie hay header. Các trường: {field_list}{note}"
                ),
            )
        ]

    # ------------------------------------------------------------------ method handling
    @staticmethod
    def _effective_method(declared: str, params: dict[str, str]) -> str:
        """Method thực tế: form POST có trường `_method` (PUT/DELETE/...) sẽ dùng giá trị override."""
        method = (declared or "GET").upper()
        if method == "POST":
            for name, value in params.items():
                if name.lower() == "_method" and value:
                    return value.strip().upper()
        return method

    def _form_method(self, form: Any) -> str | None:
        declared = (form.get("method") or "GET").strip().upper()
        override = {}
        for tag in form.find_all("input"):
            override[(tag.get("name") or "").lower()] = tag.get("value", "")
        return self._effective_method(declared, {k: v for k, v in override.items() if k == "_method"})

    # ------------------------------------------------------------------ page / form
    def _get_page(self, url: str) -> tuple[requests.Response | None, BeautifulSoup | None]:
        """GET trang một lần (cache) và parse HTML; lỗi mạng/parse chỉ ghi warning."""
        if url in self._pages:
            return self._pages[url]
        response = self.send("GET", url)
        soup: BeautifulSoup | None = None
        if response is None:
            logger.warning("CSRF: không tải được trang %s", url)
        else:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception as exc:  # noqa: BLE001 - HTML hỏng không được làm sập tiến trình
                logger.warning("CSRF: không parse được HTML của %s: %s", url, exc)
        self._pages[url] = (response, soup)
        return response, soup

    def _find_form(self, soup: BeautifulSoup, endpoint: "EndpointDescriptor", page_url: str) -> Any | None:
        """Chọn form state-changing khớp action với endpoint (ưu tiên form trùng nhiều trường nhất)."""
        try:
            wanted = URLParser.normalize(endpoint.url)
            best, best_score = None, -1
            for form in soup.find_all("form"):
                action = form.get("action")
                target = URLParser.normalize(urljoin(page_url, action)) if action else URLParser.normalize(page_url)
                if target != wanted:
                    continue
                if self._form_method(form) not in STATE_CHANGING_METHODS:
                    continue
                names = {t.get("name") for t in form.find_all(["input", "textarea", "select"]) if t.get("name")}
                score = len(names & set(endpoint.params))
                if score > best_score:
                    best, best_score = form, score
            return best
        except Exception as exc:  # noqa: BLE001
            logger.warning("CSRF: lỗi khi phân tích form tại %s: %s", endpoint.url, exc)
            return None

    # ------------------------------------------------------------------ tokens
    def _is_token_name(self, name: str) -> bool:
        return name.lower() in self._token_names or bool(TOKEN_NAME_PATTERN.search(name))

    def _collect_tokens(
        self, params: dict[str, str], form: Any | None, soup: BeautifulSoup | None
    ) -> list[_TokenCandidate]:
        """Gộp token từ params endpoint, hidden input của form và thẻ meta (không dùng riêng nguồn nào)."""
        candidates: list[_TokenCandidate] = []
        try:
            if form is not None:
                for tag in form.find_all("input"):
                    name = tag.get("name")
                    if name and (tag.get("type") or "").strip().lower() == "hidden" and self._is_token_name(name):
                        candidates.append(_TokenCandidate(name, tag.get("value", ""), "input"))
            if soup is not None:
                for tag in soup.find_all("meta"):
                    meta_name = tag.get("name") or ""
                    if META_NAME_PATTERN.search(meta_name):
                        candidates.append(_TokenCandidate(meta_name, tag.get("content", ""), "meta"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("CSRF: lỗi khi đọc token từ HTML: %s", exc)
        for name, value in params.items():
            if self._is_token_name(name):
                candidates.append(_TokenCandidate(name, value or "", "param"))
        return candidates

    # ------------------------------------------------------------------ alternatives
    @staticmethod
    def _set_cookie_headers(response: requests.Response) -> list[str]:
        try:
            return list(response.raw.headers.getlist("Set-Cookie"))
        except AttributeError:
            value = response.headers.get("Set-Cookie")
            return [value] if value else []

    def _detect_alternatives(self, response: requests.Response | None) -> _Alternatives:
        alt = _Alternatives(strong=[], samesite=[])
        if response is None:
            return alt
        for header in response.headers:
            if header.lower() in ALT_HEADER_NAMES:
                alt.strong.append(f"header {header}")
        for raw_cookie in self._set_cookie_headers(response):
            cookie_name = raw_cookie.split("=", 1)[0].strip()
            if CSRF_COOKIE_PATTERN.search(cookie_name):
                alt.strong.append(f"cookie {cookie_name}")
            match = SAMESITE_PATTERN.search(raw_cookie)
            if match:
                alt.samesite.append(f"cookie {cookie_name} SameSite={match.group(1).capitalize()}")
        return alt

    # ------------------------------------------------------------------ static token
    def _fetch_token_value(self, url: str, token_field: str) -> str | None:
        """Tải trang bằng một Session mới và lấy giá trị token của trường chỉ định."""
        with requests.Session() as fresh:
            response = self.send("GET", url, session=fresh)
        if response is None or response.status_code >= 400:
            return None
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            tag = soup.find("input", attrs={"name": token_field})
        except Exception as exc:  # noqa: BLE001
            logger.warning("CSRF: không parse được HTML của %s: %s", url, exc)
            return None
        if tag is None:
            return None
        return tag.get("value", "")

    def _is_static_token(self, url: str, token_field: str) -> bool:
        first = self._fetch_token_value(url, token_field)
        second = self._fetch_token_value(url, token_field)
        return bool(first) and first == second
