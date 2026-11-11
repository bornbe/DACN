"""
Rate limiter in-memory theo địa chỉ IP - Issue #5.1/#5.2.

LƯU Ý TRIỂN KHAI (Single-Process):
Bộ đếm rate limit lưu trong RAM của process hiện tại và được bảo vệ bằng threading.Lock.
Hệ thống chỉ hỗ trợ mô hình triển khai 1 process + nhiều luồng (ví dụ: `python app.py` hoặc
`gunicorn --workers 1 --threads N`). Không chạy nhiều worker process vì mỗi process sẽ có
bộ đếm riêng làm nhân bội quota per-IP.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from typing import Any

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue

from config.config import parse_trusted_proxies

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _compile_trusted_networks(raw_proxies: Any) -> tuple[IPNetwork, ...]:
    """Biên dịch danh sách IP/CIDR của trusted proxy thành các đối tượng mạng."""
    networks: list[IPNetwork] = []
    for entry in parse_trusted_proxies(raw_proxies):
        networks.append(ipaddress.ip_network(entry, strict=False))
    return tuple(networks)


def _is_trusted_proxy(addr: str, trusted_networks: tuple[IPNetwork, ...]) -> bool:
    """Kiểm tra một địa chỉ IP có nằm trong allowlist trusted proxy hay không."""
    if not addr or not trusted_networks:
        return False
    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip_obj in net for net in trusted_networks)


def _extract_forwarded_ip(
    forwarded_header: str,
    trusted_networks: tuple[IPNetwork, ...],
) -> str | None:
    """
    Trích xuất client IP từ X-Forwarded-For khi request đi qua trusted proxy:
    duyệt từ phải sang trái (hop gần proxy nhất), bỏ qua các hop thuộc trusted_networks
    để lấy IP client đầu tiên không thuộc trusted proxy (chống client tự chèn giả mạo ở đầu chuỗi).
    """
    if not forwarded_header:
        return None
    valid_hops: list[str] = []
    for part in forwarded_header.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        valid_hops.append(str(ip_obj))
    if not valid_hops:
        return None
    for hop in reversed(valid_hops):
        if not _is_trusted_proxy(hop, trusted_networks):
            return hop
    return valid_hops[0]


def init_rate_limiter(
    app: Flask,
    limit: int = 60,
    window_seconds: int = 60,
    trusted_proxies: Any = None,
) -> None:
    """Giới hạn số request mỗi IP trong một cửa sổ trượt (in-memory, single-process)."""
    requests_by_ip: dict[str, deque[float]] = {}
    lock = threading.Lock()
    last_sweep = [0.0]

    raw_proxies = trusted_proxies if trusted_proxies is not None else app.config.get("TRUSTED_PROXIES")
    trusted_networks = _compile_trusted_networks(raw_proxies)
    if app.config.get("TRUSTED_PROXY") and not trusted_networks:
        app.logger.warning(
            "TRUSTED_PROXY được bật nhưng TRUSTED_PROXIES trống; "
            "bỏ qua X-Forwarded-For để tránh giả mạo IP từ client trực tiếp."
        )

    def _client_ip() -> str:
        """
        Xác định IP của client để áp dụng rate limit:
        - Chỉ đọc X-Forwarded-For khi `request.remote_addr` nằm trong allowlist `TRUSTED_PROXIES`.
        - Nếu không có trusted proxy hoặc `remote_addr` không thuộc allowlist, luôn dùng `request.remote_addr`.
        """
        remote_addr = (request.remote_addr or "").strip()
        if _is_trusted_proxy(remote_addr, trusted_networks):
            forwarded = request.headers.get("X-Forwarded-For", "")
            forwarded_ip = _extract_forwarded_ip(forwarded, trusted_networks)
            if forwarded_ip:
                return forwarded_ip
        return remote_addr or "unknown"

    def _sweep(now: float) -> None:
        """Định kỳ dọn các IP không còn request nào trong cửa sổ trượt để tránh rò rỉ bộ nhớ."""
        if now - last_sweep[0] < window_seconds:
            return
        stale = [
            ip for ip, stamps in requests_by_ip.items()
            if not stamps or now - stamps[-1] >= window_seconds
        ]
        for ip in stale:
            del requests_by_ip[ip]
        last_sweep[0] = now

    @app.before_request
    def enforce_rate_limit() -> ResponseReturnValue | None:
        now = time.monotonic()
        ip_address = _client_ip()
        with lock:
            _sweep(now)
            timestamps = requests_by_ip.get(ip_address)
            if timestamps is None:
                timestamps = deque()
                requests_by_ip[ip_address] = timestamps
            while timestamps and now - timestamps[0] >= window_seconds:
                timestamps.popleft()
            if len(timestamps) >= limit:
                return jsonify(error="Too Many Requests", message="Vượt quá giới hạn request."), 429
            timestamps.append(now)
        return None
