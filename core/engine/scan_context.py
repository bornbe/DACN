"""
Ngữ cảnh quét (ScanContext) - cấu hình và kênh sự kiện dùng chung giữa Engine, CLI và Web Backend.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from config.config import Config

# Callback sự kiện: nhận một dict {"type": ..., ...}
EventCallback = Callable[[dict[str, Any]], None]


class ScanCancelled(Exception):
    """Được ném khi phiên quét bị người dùng hủy/dừng."""


@dataclass
class ScanContext:
    """
    Tham số của một phiên quét.
    Các loại sự kiện gửi qua `on_event`:
    - {"type": "status",   "status": "CRAWLING"|"SCANNING"|"COMPLETED"|"FAILED"|"CANCELLED"}
    - {"type": "progress", "percent": int, "phase": str, "message": str}
    - {"type": "finding",  "finding": dict}
    - {"type": "warning",  "message": str}
    """

    target_url: str
    max_depth: int = Config.DEFAULT_MAX_DEPTH
    max_pages: int = Config.DEFAULT_MAX_PAGES
    timeout: int = Config.DEFAULT_REQUEST_TIMEOUT
    modules: list[str] = field(default_factory=lambda: ["sqli", "xss", "csrf", "headers"])
    request_delay: float = 0.0
    target_name: str | None = None
    user_id: int | None = None
    persist: bool = False
    on_event: EventCallback | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)

    def emit(self, event_type: str, **data: Any) -> None:
        """Phát sự kiện; lỗi trong callback không được làm gián đoạn quá trình quét."""
        if self.on_event is None:
            return
        try:
            self.on_event({"type": event_type, **data})
        except Exception:  # noqa: BLE001
            pass

    def check_cancelled(self) -> None:
        if self.stop_event.is_set():
            raise ScanCancelled("Phiên quét đã bị hủy.")
