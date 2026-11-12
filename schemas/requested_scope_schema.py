"""
Kiểm tra phạm vi mục tiêu quét và module được yêu cầu - Issue #5.1/#5.2.
Tái sử dụng bộ kiểm tra dùng chung tại `core.security` để đồng bộ chính sách Loopback giữa API, CLI và Engine.
"""

from __future__ import annotations

from typing import Any

from config.config import Config
from core.security.scope_policy import MAX_SCAN_DEPTH, validate_modules
from core.security.target_validator import validate_target_url


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


__all__ = [
    "MAX_SCAN_DEPTH",
    "validate_modules",
    "validate_scan_request",
    "validate_target_url",
]
