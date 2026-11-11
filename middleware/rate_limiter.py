"""
Rate limiter in-memory theo địa chỉ IP - Issue #5.1/#5.2.

LƯU Ý (fix review - High): bộ đếm nằm trong RAM của TỪNG process. Khi triển khai nhiều
process/worker (ví dụ gunicorn --workers N), mỗi process giữ bộ đếm riêng nên giới hạn thực tế
bị nhân lên. Giải pháp production đầy đủ là dùng backend chia sẻ (ví dụ Redis). Trong phạm vi
đồ án (chạy một process + worker thread), bộ đếm được bảo vệ bằng Lock nên an toàn luồng.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue


def init_rate_limiter(app: Flask, limit: int = 60, window_seconds: int = 60) -> None:
    """Giới hạn số request mỗi IP trong một cửa sổ trượt."""
    requests_by_ip: dict[str, deque[float]] = {}
    lock = threading.Lock()
    last_sweep = [0.0]
    # Fix review (High): chỉ tin header proxy khi được cấu hình rõ ràng.
    trust_proxy = bool(app.config.get("TRUSTED_PROXY", False))

    def _client_ip() -> str:
        """Lấy IP client thật: nếu tin proxy thì đọc X-Forwarded-For, ngược lại dùng remote_addr."""
        if trust_proxy:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                client = forwarded.split(",")[0].strip()
                if client:
                    return client
        return request.remote_addr or "unknown"

    def _sweep(now: float) -> None:
        """Fix review (Thấp): định kỳ dọn các IP không còn request nào để tránh rò rỉ bộ nhớ."""
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