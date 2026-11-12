"""
Gói bảo mật cốt lõi: xác thực mục tiêu Loopback, phân giải DNS chống Rebinding,
kiểm soát phạm vi quét (Scope Policy) và làm sạch dữ liệu nhạy cảm (Data Sanitizer).
"""

from __future__ import annotations

from core.security.data_sanitizer import REDACTED, mask_sensitive_data
from core.security.dns_resolver import DNSResolutionError, resolve_hostname
from core.security.scope_policy import (
    MAX_REQUEST_TIMEOUT,
    MAX_SCAN_DEPTH,
    MAX_SCAN_PAGES,
    build_authorized_scope,
    validate_modules,
    validate_redirect_target,
)
from core.security.target_validator import (
    SSRFBlockedError,
    TargetValidationError,
    is_loopback_hostname,
    is_loopback_ip,
    validate_resolved_ips,
    validate_target_url,
)

__all__ = [
    "DNSResolutionError",
    "MAX_REQUEST_TIMEOUT",
    "MAX_SCAN_DEPTH",
    "MAX_SCAN_PAGES",
    "REDACTED",
    "SSRFBlockedError",
    "TargetValidationError",
    "build_authorized_scope",
    "is_loopback_hostname",
    "is_loopback_ip",
    "mask_sensitive_data",
    "resolve_hostname",
    "validate_modules",
    "validate_redirect_target",
    "validate_resolved_ips",
    "validate_target_url",
]
