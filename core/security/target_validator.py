"""
Kiểm tra mục tiêu quét theo chính sách an toàn Lab:
Chỉ cho phép `localhost`, tên miền `.localhost` hoặc địa chỉ loopback (`127.0.0.0/8`, `::1`).
Chặn tuyệt đối mọi địa chỉ Internet, mạng nội bộ Private (`10/8`, `172.16/12`, `192.168/16`),
Link-Local / Cloud Metadata (`169.254.0.0/16`, `169.254.169.254`, `fe80::/10`) và thông tin xác thực trong URL.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from core.security.dns_resolver import DNSResolutionError, ResolverFunc, resolve_hostname

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")


class TargetValidationError(ValueError):
    """Lỗi khi URL hoặc mục tiêu quét vi phạm chính sách an toàn."""


class SSRFBlockedError(TargetValidationError):
    """Lỗi khi phát hiện mục tiêu, DNS hoặc redirect trỏ ra ngoài phạm vi loopback an toàn."""


def is_loopback_ip(ip_value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Trả về True CHỈ KHI địa chỉ IP nằm trong dải loopback (`127.0.0.0/8` hoặc `::1`).
    Từ chối mọi địa chỉ unspecified (`0.0.0.0`, `::`), private LAN, link-local/metadata và public IP.
    """
    try:
        if isinstance(ip_value, str):
            cleaned = ip_value.strip().strip("[]").split("%")[0]
            addr = ipaddress.ip_address(cleaned)
        else:
            addr = ip_value
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        return False
    return bool(addr.is_loopback)


def is_loopback_hostname(hostname: str) -> bool:
    """
    Kiểm tra hostname có phải `localhost`, `*.localhost` hợp lệ hoặc địa chỉ IP loopback hay không.
    """
    host = (hostname or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        return False
    if host == "localhost":
        return True
    if host.endswith(".localhost"):
        prefix = host[: -len(".localhost")]
        if not prefix or prefix.startswith(".") or prefix.endswith(".") or ".." in prefix:
            return False
        labels = prefix.split(".")
        return all(bool(_HOSTNAME_LABEL_RE.match(label)) for label in labels)
    return is_loopback_ip(host)


def validate_resolved_ips(hostname: str, ips: list[str]) -> list[str]:
    """
    Xác minh mọi địa chỉ IP phân giải được từ hostname đều thuộc loopback.
    Nếu có bất kỳ IP nào ngoài loopback (ví dụ `192.168.1.1`, `169.254.169.254`, IP public),
    ném `SSRFBlockedError` ngay lập tức.
    """
    if not ips:
        raise SSRFBlockedError("Không phân giải được địa chỉ IP hợp lệ cho mục tiêu.")
    for ip_str in ips:
        if not is_loopback_ip(ip_str):
            raise SSRFBlockedError(
                f"Mục tiêu bị từ chối vì phân giải tới địa chỉ ngoài loopback ({ip_str})."
            )
    return ips


def validate_target_url(
    value: Any,
    *,
    resolve_dns: bool = True,
    resolver: ResolverFunc | None = None,
) -> str:
    """
    Điểm kiểm tra URL mục tiêu dùng chung cho Web API, CLI, ScanEngine, Crawler và SafeHTTPClient:
    1. Chỉ chấp nhận chuỗi URL có scheme `http` hoặc `https`.
    2. Từ chối URL chứa ký tự điều khiển/khoảng trắng hoặc chứa `username`/`password`.
       Thông báo lỗi không bao giờ phản chiếu lại mật khẩu/secret trong URL.
    3. Kiểm tra cổng hợp lệ (`1..65535`).
    4. Chỉ chấp nhận hostname `localhost`, `*.localhost` hoặc IP loopback (`127.0.0.0/8`, `::1`).
    5. Khi `resolve_dns=True`, phân giải DNS và từ chối nếu bất kỳ IP nào không thuộc loopback.
    """
    if not isinstance(value, str) or not value.strip():
        raise TargetValidationError("url là bắt buộc.")
    url = value.strip()
    if _CONTROL_OR_SPACE_RE.search(url):
        raise TargetValidationError("URL không hợp lệ (chứa khoảng trắng hoặc ký tự điều khiển).")

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        _ = parsed.port
    except ValueError as exc:
        raise TargetValidationError("URL không hợp lệ.") from exc

    scheme = (parsed.scheme or "").lower()
    if (
        scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in (parsed.netloc or "")
    ):
        raise TargetValidationError(
            "URL phải dùng HTTP(S), có hostname và không chứa thông tin xác thực."
        )

    if not is_loopback_hostname(hostname):
        raise SSRFBlockedError(
            "Chỉ chấp nhận mục tiêu lab trên localhost hoặc địa chỉ loopback."
        )

    if resolve_dns:
        try:
            ips = resolve_hostname(hostname, resolver=resolver)
        except DNSResolutionError as exc:
            raise SSRFBlockedError(
                "Không thể xác minh DNS an toàn cho hostname mục tiêu."
            ) from exc
        validate_resolved_ips(hostname, ips)

    return url
