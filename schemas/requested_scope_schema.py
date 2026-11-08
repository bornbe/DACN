"""
Kiểm tra phạm vi mục tiêu quét và module được yêu cầu - Issue #5.1/#5.2.
Chỉ cho phép host loopback/localhost để API phục vụ môi trường lab cục bộ.
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from config.config import Config
from core.scanners import ALL_MODULES

MAX_SCAN_DEPTH = 5


def validate_target_url(value: Any) -> str:
    """Chỉ chấp nhận URL HTTP(S) trỏ tới loopback hoặc tên miền localhost."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("url là bắt buộc.")
    url = value.strip()
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        parsed.port
    except ValueError as exc:
        raise ValueError("URL không hợp lệ.") from exc
    if parsed.scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
        raise ValueError("URL phải dùng HTTP(S), có hostname và không chứa thông tin xác thực.")
    is_localhost = hostname == "localhost" or hostname.endswith(".localhost")
    try:
        is_loopback_ip = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback_ip = False
    if not (is_localhost or is_loopback_ip):
        raise ValueError("Chỉ chấp nhận mục tiêu lab trên localhost hoặc địa chỉ loopback.")
    return url


def validate_modules(value: Any) -> list[str]:
    """Kiểm tra danh sách module theo registry ALL_MODULES."""
    if value is None:
        return list(ALL_MODULES)
    if not isinstance(value, list) or any(not isinstance(module, str) for module in value):
        raise ValueError("modules phải là danh sách tên module.")
    modules: list[str] = []
    for module in value:
        normalized = module.strip().lower()
        if normalized not in ALL_MODULES:
            raise ValueError(f"Module không được hỗ trợ: {module}.")
        if normalized not in modules:
            modules.append(normalized)
    return modules or list(ALL_MODULES)


def validate_scan_request(data: Any) -> dict[str, Any]:
    """Kiểm tra và chuẩn hóa payload tạo phiên quét."""
    if not isinstance(data, dict):
        raise ValueError("JSON body phải là một object.")
    url = validate_target_url(data.get("url"))
    max_depth = data.get("max_depth", Config.DEFAULT_MAX_DEPTH)
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 0 <= max_depth <= MAX_SCAN_DEPTH:
        raise ValueError(f"max_depth phải là số nguyên từ 0 đến {MAX_SCAN_DEPTH}.")
    return {
        "url": url,
        "max_depth": max_depth,
        "modules": validate_modules(data.get("modules")),
    }