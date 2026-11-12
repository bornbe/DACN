"""
Ghim kết nối HTTP vào đúng địa chỉ IP loopback đã xác minh (Socket IP Pinning) - P1a.

Lỗ hổng gốc (TOCTOU / DNS Rebinding): sau khi phân giải + xác minh DNS trả về loopback,
nếu vẫn mở socket bằng *hostname* thì `requests`/`urllib3` sẽ phân giải DNS **một lần nữa**
lúc kết nối, nên IP thực tế khi kết nối có thể đã bị đổi sang IP ngoài loopback
(ví dụ `169.254.169.254`) — việc ghim header `Host` không ngăn được điều này.

Giải pháp: phân giải lại DNS ngay trước khi kết nối, xác minh toàn bộ IP là loopback, rồi
mở socket **thẳng tới IP literal vừa xác minh**, đồng thời giữ header `Host` = hostname gốc
để máy chủ vẫn định tuyến đúng virtual host.

Hạn chế đã biết (giải pháp fail-closed theo đúng yêu cầu checklist): với `https` tới một
*hostname*, `requests` không thể vừa ghim IP vừa giữ nguyên SNI/kiểm tra chứng chỉ một cách
an toàn (không được phép dùng `verify=False`), nên module này **TỪ CHỐI** trường hợp đó
(`SSRFBlockedError`). `https` chỉ được chấp nhận khi mục tiêu đã là IP loopback literal
(ví dụ `https://127.0.0.1:8443`). Môi trường Lab mặc định dùng `http` tới localhost nên
không bị ảnh hưởng.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from core.security.dns_resolver import ResolverFunc, resolve_hostname
from core.security.target_validator import (
    SSRFBlockedError,
    TargetValidationError,
    validate_resolved_ips,
)


@dataclass(frozen=True)
class PinnedConnection:
    """Kết quả ghim kết nối."""

    connect_url: str  # URL dùng để mở socket (host đã thay bằng IP loopback đã xác minh)
    host_header: str  # Giá trị header `Host` cần giữ (hostname gốc, kèm cổng nếu có)
    pinned_ip: str  # IP loopback thực tế được ghim


def _is_ip_literal(host: str) -> bool:
    """True nếu `host` đã là một địa chỉ IP (không phải tên miền cần phân giải)."""
    try:
        ipaddress.ip_address(host.strip().strip("[]").split("%")[0])
        return True
    except ValueError:
        return False


def _prefer_ipv4(ips: list[str]) -> str:
    """Ưu tiên IPv4 loopback (máy chủ Lab thường lắng nghe trên 127.0.0.1)."""
    for ip in ips:
        if ":" not in ip:
            return ip
    return ips[0]


def resolve_pinned_connection(
    url: str,
    *,
    resolver: ResolverFunc | None = None,
) -> PinnedConnection:
    """
    Phân giải lại DNS ngay trước khi kết nối (chống DNS Rebinding), xác minh mọi IP thuộc
    loopback, rồi trả về `PinnedConnection` gồm URL đã ghim IP và header `Host` gốc.

    Ném:
    - `SSRFBlockedError`: DNS phân giải ra IP ngoài loopback, hoặc là `https` tới hostname.
    - `TargetValidationError`: URL thiếu scheme `http(s)` hoặc hostname hợp lệ.
    - `DNSResolutionError`: không thể phân giải hostname.
    """
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        raise TargetValidationError(
            "URL cần scheme http(s) và hostname hợp lệ để ghim kết nối."
        )

    # Bước chống rebinding: phân giải lại và xác minh toàn bộ IP là loopback (ném nếu vi phạm)
    ips = resolve_hostname(host, resolver=resolver)
    validate_resolved_ips(host, ips)

    # `Host` giữ nguyên netloc gốc; userinfo đã bị chặn từ `validate_target_url` phía trước
    host_header = parsed.netloc

    # Hostname vốn đã là IP literal: kết nối đã được ghim sẵn, không cần viết lại URL
    if _is_ip_literal(host):
        return PinnedConnection(connect_url=url, host_header=host_header, pinned_ip=host)

    # Fail-closed: https tới hostname không thể vừa ghim IP vừa giữ SNI/chứng chỉ an toàn
    if scheme == "https":
        raise SSRFBlockedError(
            "Chế độ Lab chỉ ghim kết nối HTTPS khi mục tiêu là IP loopback trực tiếp "
            "(ví dụ https://127.0.0.1). Từ chối HTTPS tới hostname để không mất ghim IP."
        )

    pinned_ip = _prefer_ipv4(ips)
    connect_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    connect_netloc = f"{connect_host}:{parsed.port}" if parsed.port else connect_host
    connect_url = urlunsplit((scheme, connect_netloc, parsed.path or "", parsed.query, ""))
    return PinnedConnection(connect_url=connect_url, host_header=host_header, pinned_ip=pinned_ip)