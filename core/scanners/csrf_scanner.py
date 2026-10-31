"""
Module phát hiện Anti-CSRF Token Missing - Issue #3.3.
Lọc các form thay đổi trạng thái (POST/PUT/DELETE), tìm trường token CSRF hợp lệ theo
pattern tên (csrf, xsrf, token, authenticity_token...) và gắn nhãn lỗ hổng khi form không
có token, token rỗng/yếu hoặc token cố định giữa các phiên truy cập.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import requests
from bs4 import BeautifulSoup

from core.scanners.base_scanner import BaseScanner, Finding

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Pattern tên trường nghi là token CSRF
TOKEN_NAME_PATTERN = re.compile(r"csrf|xsrf|authenticity_token|requestverificationtoken|token", re.I)

# Giá trị giữ chỗ không phải token thật
PLACEHOLDER_VALUES = frozenset({"", "token", "null", "none", "undefined", "csrf", "test", "0", "1", "true", "false"})
MIN_TOKEN_LENGTH = 8


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

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        if endpoint.method.upper() not in STATE_CHANGING_METHODS:
            return []

        signature = endpoint.signature()
        if signature in self._seen_forms:
            return []
        self._seen_forms.add(signature)

        token_field = self._find_token_field(endpoint.params)
        field_list = ", ".join(endpoint.params) or "(không có trường)"

        if token_field is None:
            return [
                self.make_finding(
                    vuln_name="Anti-CSRF Token Missing",
                    target_url=endpoint.url,
                    evidence=(
                        f"Form {endpoint.method} tới {endpoint.url} không chứa trường token CSRF. "
                        f"Các trường: {field_list}"
                    ),
                )
            ]

        value = (endpoint.params.get(token_field) or "").strip()
        if value.lower() in PLACEHOLDER_VALUES or len(value) < MIN_TOKEN_LENGTH:
            return [
                self.make_finding(
                    vuln_name="Anti-CSRF Token Empty or Weak",
                    target_url=endpoint.url,
                    parameter=token_field,
                    evidence=f"Trường '{token_field}' có giá trị rỗng/giữ chỗ/quá ngắn: '{value}'",
                )
            ]

        if self.check_static_token and self._is_static_token(endpoint.url, token_field):
            return [
                self.make_finding(
                    vuln_name="Anti-CSRF Token Static",
                    target_url=endpoint.url,
                    parameter=token_field,
                    evidence=(
                        f"Trường '{token_field}' có cùng giá trị ở hai phiên truy cập độc lập, "
                        "cho thấy token cố định thay vì gắn với phiên làm việc."
                    ),
                )
            ]
        return []

    def _find_token_field(self, params: dict[str, str]) -> str | None:
        """Tìm tên trường nghi là token CSRF (ưu tiên danh sách chuẩn trong danh mục OWASP)."""
        for name in params:
            if name.lower() in self._token_names:
                return name
        for name in params:
            if TOKEN_NAME_PATTERN.search(name):
                return name
        return None

    def _fetch_token_value(self, url: str, token_field: str) -> str | None:
        """Tải trang bằng một Session mới và lấy giá trị token của trường chỉ định."""
        with requests.Session() as fresh:
            response = self.send("GET", url, session=fresh)
        if response is None or response.status_code >= 400:
            return None
        soup = BeautifulSoup(response.text, "html.parser")
        tag = soup.find("input", attrs={"name": token_field})
        if tag is None:
            return None
        return tag.get("value", "")

    def _is_static_token(self, url: str, token_field: str) -> bool:
        first = self._fetch_token_value(url, token_field)
        second = self._fetch_token_value(url, token_field)
        return bool(first) and first == second
