"""
Kiểm thử ghim kết nối theo IP loopback (Socket IP Pinning) - P1a.
Dùng resolver tiêm (injection) để kiểm chứng hoàn toàn offline, không gọi DNS/mạng thật.
"""

from __future__ import annotations

import pytest

from core.security.connection_pinning import resolve_pinned_connection
from core.security.target_validator import SSRFBlockedError, TargetValidationError


def _resolver(*ips: str):
    return lambda _host: list(ips)


def test_ip_literal_target_is_left_unchanged():
    """Mục tiêu đã là IP loopback literal: không cần viết lại URL, giữ nguyên để kết nối."""
    pinned = resolve_pinned_connection("http://127.0.0.1:8080/path?q=1", resolver=_resolver("127.0.0.1"))
    assert pinned.connect_url == "http://127.0.0.1:8080/path?q=1"
    assert pinned.host_header == "127.0.0.1:8080"
    assert pinned.pinned_ip == "127.0.0.1"


def test_hostname_is_rewritten_to_verified_loopback_ip():
    """Hostname loopback được thay bằng IP đã xác minh, nhưng header Host giữ nguyên hostname gốc."""
    pinned = resolve_pinned_connection(
        "http://app.localhost:8080/login?next=/a", resolver=_resolver("127.0.0.1")
    )
    assert pinned.connect_url == "http://127.0.0.1:8080/login?next=/a"
    assert pinned.host_header == "app.localhost:8080"
    assert pinned.pinned_ip == "127.0.0.1"


def test_resolution_to_non_loopback_is_blocked():
    """DNS trả về IP ngoài loopback (rebinding) phải bị chặn trước khi kết nối."""
    for bad_ip in ("10.0.0.5", "192.168.1.100", "169.254.169.254", "93.184.216.34"):
        with pytest.raises(SSRFBlockedError):
            resolve_pinned_connection("http://evil.localhost:8080/x", resolver=_resolver(bad_ip))


def test_https_to_hostname_is_fail_closed():
    """https tới hostname bị từ chối (không thể vừa ghim IP vừa giữ SNI an toàn)."""
    with pytest.raises(SSRFBlockedError, match="HTTPS"):
        resolve_pinned_connection("https://app.localhost:8443/", resolver=_resolver("127.0.0.1"))


def test_https_to_ip_literal_is_allowed_unchanged():
    """https tới IP loopback literal vẫn được chấp nhận và giữ nguyên URL."""
    pinned = resolve_pinned_connection("https://127.0.0.1:8443/api", resolver=_resolver("127.0.0.1"))
    assert pinned.connect_url == "https://127.0.0.1:8443/api"
    assert pinned.pinned_ip == "127.0.0.1"


def test_ipv6_loopback_hostname_is_bracketed():
    """IP loopback IPv6 phải được bọc trong dấu ngoặc vuông khi dựng netloc kết nối."""
    pinned = resolve_pinned_connection("http://app.localhost:8080/x", resolver=_resolver("::1"))
    assert pinned.connect_url == "http://[::1]:8080/x"
    assert pinned.pinned_ip == "::1"


def test_prefers_ipv4_when_both_families_resolved():
    """Khi hostname phân giải ra cả IPv6 và IPv4 loopback, ưu tiên ghim IPv4."""
    pinned = resolve_pinned_connection("http://localhost:3000/", resolver=_resolver("::1", "127.0.0.1"))
    assert pinned.connect_url == "http://127.0.0.1:3000/"
    assert pinned.pinned_ip == "127.0.0.1"


def test_invalid_scheme_is_rejected():
    """URL không có scheme http(s) hợp lệ bị từ chối."""
    with pytest.raises(TargetValidationError):
        resolve_pinned_connection("ftp://127.0.0.1/x", resolver=_resolver("127.0.0.1"))