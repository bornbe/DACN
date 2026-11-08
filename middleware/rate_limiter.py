"""
Rate limiter in-memory theo địa chỉ IP - Issue #5.1/#5.2.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue


def init_rate_limiter(app: Flask, limit: int = 60, window_seconds: int = 60) -> None:
    """Giới hạn số request mỗi IP trong một cửa sổ trượt."""
    requests_by_ip: defaultdict[str, deque[float]] = defaultdict(deque)
    lock = threading.Lock()

    @app.before_request
    def enforce_rate_limit() -> ResponseReturnValue | None:
        now = time.monotonic()
        ip_address = request.remote_addr or "unknown"
        with lock:
            timestamps = requests_by_ip[ip_address]
            while timestamps and now - timestamps[0] >= window_seconds:
                timestamps.popleft()
            if len(timestamps) >= limit:
                return jsonify(error="Too Many Requests", message="Vượt quá giới hạn request."), 429
            timestamps.append(now)
        return None