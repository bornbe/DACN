"""
Chính sách kiểm soát phạm vi quét (Scope Policy) dùng chung cho API, CLI, Engine và HTTP Client.
Đảm bảo cô lập phạm vi (Scope Isolation), giới hạn tài nguyên và xác thực từng bước chuyển hướng (Redirect).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

from config.config import Config
from core.crawler.url_parser import URLParser
from core.scanners import ALL_MODULES
from core.security.dns_resolver import ResolverFunc
from core.security.target_validator import (
    SSRFBlockedError,
    TargetValidationError,
    validate_target_url,
)

MAX_SCAN_DEPTH = 5
MAX_SCAN_PAGES = 500
MAX_REQUEST_TIMEOUT = 60


def validate_modules(value: Any) -> list[str]:
    """
    Kiểm tra danh sách module theo registry chính thức `ALL_MODULES`.
    Từ chối mọi module không tồn tại hoặc bị vô hiệu hóa vì lý do an toàn (như `ssrf`).
    """
    if value is None:
        return list(ALL_MODULES)
    if not isinstance(value, list) or any(not isinstance(module, str) for module in value):
        raise ValueError("modules phải là danh sách tên module.")
    modules: list[str] = []
    for module in value:
        normalized = module.strip().lower()
        if normalized not in ALL_MODULES:
            raise ValueError(
                f"Module không được hỗ trợ: {module}. Các module hỗ trợ: {', '.join(ALL_MODULES)}."
            )
        if normalized not in modules:
            modules.append(normalized)
    return modules or list(ALL_MODULES)


def build_authorized_scope(
    requested_scope: dict[str, Any],
    *,
    clamp_limits: bool = True,
    resolve_dns: bool = True,
    resolver: ResolverFunc | None = None,
) -> dict[str, Any]:
    """
    Biến đổi `requested_scope` từ phía client thành `authorized_scope` an toàn:
    - Xác thực URL mục tiêu bắt buộc thuộc loopback/localhost.
    - Loại bỏ/ghi đè mọi cờ nguy hiểm do client tự chèn (ví dụ `allowed_domains`,
      `allow_private_ip`, `follow_external_redirects`, `verify_tls=False`).
    - Áp đặt giới hạn cứng cho `max_depth`, `max_pages` và `timeout`.
    """
    if not isinstance(requested_scope, dict):
        raise ValueError("JSON body phải là một object.")

    url = validate_target_url(
        requested_scope.get("url"),
        resolve_dns=resolve_dns,
        resolver=resolver,
    )
    normalized_url = URLParser.normalize(url)
    parsed = urlsplit(normalized_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    raw_depth = requested_scope.get("max_depth", Config.DEFAULT_MAX_DEPTH)
    if isinstance(raw_depth, bool) or not isinstance(raw_depth, int):
        raise ValueError(f"max_depth phải là số nguyên từ 0 đến {MAX_SCAN_DEPTH}.")
    if clamp_limits:
        max_depth = min(max(raw_depth, 0), MAX_SCAN_DEPTH)
    else:
        if not 0 <= raw_depth <= MAX_SCAN_DEPTH:
            raise ValueError(f"max_depth phải là số nguyên từ 0 đến {MAX_SCAN_DEPTH}.")
        max_depth = raw_depth

    raw_pages = requested_scope.get("max_pages", Config.DEFAULT_MAX_PAGES)
    if isinstance(raw_pages, bool) or not isinstance(raw_pages, int) or raw_pages < 1:
        max_pages = Config.DEFAULT_MAX_PAGES
    else:
        max_pages = min(raw_pages, MAX_SCAN_PAGES)

    raw_timeout = requested_scope.get("timeout", Config.DEFAULT_REQUEST_TIMEOUT)
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int) or raw_timeout < 1:
        timeout = Config.DEFAULT_REQUEST_TIMEOUT
    else:
        timeout = min(raw_timeout, MAX_REQUEST_TIMEOUT)

    modules = validate_modules(requested_scope.get("modules"))

    return {
        "url": url,
        "normalized_url": normalized_url,
        "allowed_domains": [hostname],
        "max_depth": max_depth,
        "max_pages": max_pages,
        "timeout": timeout,
        "modules": modules,
        "loopback_only": True,
        "verify_tls": True,
        "follow_external_redirects": False,
    }


def validate_redirect_target(
    origin_url: str,
    current_url: str,
    location_header: str,
    *,
    resolve_dns: bool = True,
    resolver: ResolverFunc | None = None,
) -> str:
    """
    Kiểm tra đích chuyển hướng (HTTP 3xx Location):
    1. Giải mã URL tương đối theo `current_url` và chuẩn hóa.
    2. Xác thực đích chuyển hướng phải tuân thủ chính sách loopback & DNS an toàn.
    3. Xác thực đích chuyển hướng vẫn nằm trong cùng scope (hostname & port) của `origin_url`.
    Ném `SSRFBlockedError` hoặc `TargetValidationError` nếu không hợp lệ.
    """
    loc = (location_header or "").strip()
    if not loc:
        raise TargetValidationError("Header Location chuyển hướng trống.")

    candidate = urljoin(current_url, loc)
    validate_target_url(candidate, resolve_dns=resolve_dns, resolver=resolver)
    normalized_target = URLParser.normalize(candidate)

    scope_parser = URLParser(origin_url)
    if not scope_parser.is_in_scope(normalized_target):
        raise SSRFBlockedError(
            f"Chặn redirect ra ngoài phạm vi mục tiêu: {current_url} -> {normalized_target}"
        )
    return normalized_target
