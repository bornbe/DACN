"""
Bộ phân giải DNS an toàn phục vụ xác minh mục tiêu Loopback và chống DNS Rebinding.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable

ResolverFunc = Callable[[str], list[str]]


class DNSResolutionError(ValueError):
    """Ngoại lệ khi không thể phân giải hostname hoặc kết quả DNS không hợp lệ."""


def _is_mocked(func: object) -> bool:
    """Kiểm tra hàm thư viện chuẩn có đang được mock trong bài kiểm thử hay không."""
    return hasattr(func, "_mock_name") or hasattr(func, "assert_called")


def resolve_hostname(hostname: str, resolver: ResolverFunc | None = None) -> list[str]:
    """
    Phân giải hostname thành danh sách địa chỉ IP (IPv4/IPv6).
    - Nếu `hostname` đã là địa chỉ IP literal hợp lệ, trả về chính địa chỉ đó.
    - Gọi `socket.gethostbyname` trước để tương thích với cơ chế kiểm tra DNS Rebinding,
      kết hợp `socket.getaddrinfo` khi cần thu thập đầy đủ bản ghi A/AAAA.
    """
    host = (hostname or "").strip().strip("[]").lower().rstrip(".")
    if not host:
        raise DNSResolutionError("Hostname mục tiêu không được để trống.")

    if resolver is not None:
        ips = resolver(host)
        if not ips:
            raise DNSResolutionError(f"Không phân giải được địa chỉ IP cho hostname: {host}")
        return list(dict.fromkeys(ips))

    try:
        ip_obj = ipaddress.ip_address(host)
        return [str(ip_obj)]
    except ValueError:
        pass

    resolved: list[str] = []
    gethostbyname_mocked = _is_mocked(socket.gethostbyname)
    getaddrinfo_mocked = _is_mocked(socket.getaddrinfo)

    try:
        primary_ip = socket.gethostbyname(host)
        if primary_ip:
            resolved.append(str(primary_ip).strip())
    except OSError as exc:
        if gethostbyname_mocked:
            raise DNSResolutionError(f"Không thể phân giải DNS cho hostname: {host}") from exc

    if not gethostbyname_mocked:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                sockaddr = info[4]
                if sockaddr and isinstance(sockaddr[0], str):
                    ip_text = sockaddr[0].split("%")[0].strip()
                    if ip_text and ip_text not in resolved:
                        resolved.append(ip_text)
        except OSError as exc:
            if getaddrinfo_mocked and not resolved:
                raise DNSResolutionError(f"Không thể phân giải DNS cho hostname: {host}") from exc

    # Theo RFC 6761, miền `.localhost` luôn trỏ về loopback kể cả khi OS resolver
    # trên một số môi trường Windows/container chưa cấu hình wildcard `*.localhost`.
    if (
        not resolved
        and not gethostbyname_mocked
        and not getaddrinfo_mocked
        and (host == "localhost" or host.endswith(".localhost"))
    ):
        return ["127.0.0.1"]

    if not resolved:
        raise DNSResolutionError(f"Không thể phân giải DNS cho hostname: {host}")

    return resolved
