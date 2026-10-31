"""
Module kiểm tra cấu hình HTTP Security Headers - Issue #3.2.
Gửi request tới trang gốc (root) của từng Origin, phân tích HTTP Response Headers:
HSTS, CSP, X-Frame-Options, X-Content-Type-Options (+ Referrer-Policy, Permissions-Policy).
"""

from __future__ import annotations

import re
import threading
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import requests

from core.scanners.base_scanner import BaseScanner, Finding

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

# HSTS khuyến nghị tối thiểu 1 năm
HSTS_RECOMMENDED_MAX_AGE = 31536000


class SecurityHeadersScanner(BaseScanner):
    """Phát hiện header bảo mật bị thiếu hoặc cấu hình lỏng lẻo (mỗi Origin kiểm tra một lần)."""

    category = "security_headers"
    name = "headers"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._checked_origins: set[str] = set()
        self._lock = threading.Lock()
        self._specs: dict[str, dict[str, str]] = {}
        try:
            for spec in self.payload_loader.load_security_headers_spec():
                self._specs[spec["header"].lower()] = spec
        except Exception:  # noqa: BLE001 - thiếu tệp cấu hình thì dùng giá trị mặc định
            self._specs = {}

    def reset(self) -> None:
        """Bắt đầu phiên quét mới: xóa tập Origin đã kiểm tra (dưới lock để an toàn đa luồng)."""
        with self._lock:
            self._checked_origins.clear()

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        parsed = urlparse(endpoint.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return []
        origin = f"{parsed.scheme}://{parsed.netloc}"

        with self._lock:
            if origin in self._checked_origins:
                return []
            self._checked_origins.add(origin)

        root_url = origin + "/"
        response = self.send("GET", root_url)
        if response is None:
            with self._lock:  # cho phép thử lại ở endpoint khác khi lỗi mạng
                self._checked_origins.discard(origin)
            return []
        return self.analyze_headers(response, root_url)

    # ------------------------------------------------------------------ analysis
    def analyze_headers(self, response: requests.Response, url: str) -> list[Finding]:
        headers = response.headers
        is_https = urlparse(response.url or url).scheme == "https"
        findings: list[Finding] = []

        findings += self._check_hsts(headers, url, is_https)
        findings += self._check_csp(headers, url)
        findings += self._check_x_frame_options(headers, url)
        findings += self._check_x_content_type_options(headers, url)
        for optional in ("Referrer-Policy", "Permissions-Policy"):
            if optional not in headers:
                findings.append(self._missing(optional, url))
        return findings

    def _spec(self, header: str) -> dict[str, str]:
        return self._specs.get(header.lower(), {})

    def _missing(self, header: str, url: str) -> Finding:
        spec = self._spec(header)
        recommended = spec.get("recommended")
        return self.make_finding(
            vuln_name=f"Missing Security Header: {header}",
            target_url=url,
            severity=spec.get("severity", "LOW"),
            parameter=header,
            evidence=f"Header '{header}' không có trong phản hồi HTTP."
            + (f" Giá trị khuyến nghị: {recommended}" if recommended else ""),
            cwe_id=spec.get("cwe_id"),
            remediation=spec.get("remediation"),
        )

    def _weak(self, header: str, value: str, reason: str, url: str, severity: str = "LOW") -> Finding:
        spec = self._spec(header)
        return self.make_finding(
            vuln_name=f"Weak Security Header: {header}",
            target_url=url,
            severity=severity,
            parameter=header,
            evidence=f"{header}: {value} -> {reason}",
            cwe_id=spec.get("cwe_id"),
            remediation=spec.get("remediation"),
        )

    def _check_hsts(self, headers: Any, url: str, is_https: bool) -> list[Finding]:
        header = "Strict-Transport-Security"
        # HSTS chỉ có hiệu lực trên HTTPS; trình duyệt bỏ qua header này trên HTTP thuần
        if not is_https:
            return []
        value = headers.get(header)
        if value is None:
            return [self._missing(header, url)]

        findings: list[Finding] = []
        match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
        if not match:
            findings.append(self._weak(header, value, "thiếu tham số max-age", url, "MEDIUM"))
        elif int(match.group(1)) < HSTS_RECOMMENDED_MAX_AGE:
            findings.append(
                self._weak(
                    header,
                    value,
                    f"max-age={match.group(1)} thấp hơn khuyến nghị {HSTS_RECOMMENDED_MAX_AGE}",
                    url,
                )
            )
        if "includesubdomains" not in value.lower():
            findings.append(self._weak(header, value, "thiếu includeSubDomains", url, "INFO"))
        return findings

    def _check_csp(self, headers: Any, url: str) -> list[Finding]:
        header = "Content-Security-Policy"
        value = headers.get(header)
        if value is None:
            return [self._missing(header, url)]

        issues: list[str] = []
        for directive in value.split(";"):
            parts = directive.strip().split()
            if not parts:
                continue
            name, sources = parts[0].lower(), [s.lower() for s in parts[1:]]
            if "'unsafe-inline'" in sources:
                issues.append(f"{name} cho phép 'unsafe-inline'")
            if "'unsafe-eval'" in sources:
                issues.append(f"{name} cho phép 'unsafe-eval'")
            if "*" in sources:
                issues.append(f"{name} cho phép nguồn wildcard '*'")
        if not issues:
            return []
        return [self._weak(header, value, "; ".join(issues), url)]

    def _check_x_frame_options(self, headers: Any, url: str) -> list[Finding]:
        header = "X-Frame-Options"
        value = headers.get(header)
        if value is None:
            # CSP frame-ancestors là cơ chế thay thế hợp lệ chống Clickjacking
            if "frame-ancestors" in headers.get("Content-Security-Policy", "").lower():
                return []
            return [self._missing(header, url)]
        if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
            return [self._weak(header, value, "giá trị phải là DENY hoặc SAMEORIGIN", url)]
        return []

    def _check_x_content_type_options(self, headers: Any, url: str) -> list[Finding]:
        header = "X-Content-Type-Options"
        value = headers.get(header)
        if value is None:
            return [self._missing(header, url)]
        if value.strip().lower() != "nosniff":
            return [self._weak(header, value, "giá trị bắt buộc là nosniff", url)]
        return []
