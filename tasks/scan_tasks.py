"""
Hàng đợi scan nền bằng queue.Queue và một worker thread - Issue #5.2.
"""

from __future__ import annotations

import logging
import queue
import threading

from services.scan_service import mark_scan_failed, run_scan

logger = logging.getLogger(__name__)
_scan_queue: queue.Queue[int] = queue.Queue()
_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None


def _worker_loop() -> None:
    """Lấy và xử lý job liên tục; lỗi mỗi job không làm chết worker."""
    while True:
        session_id = _scan_queue.get()
        try:
            run_scan(session_id)
        except Exception as exc:
            logger.exception("Lỗi không mong đợi khi xử lý scan job %s", session_id)
            try:
                mark_scan_failed(session_id, str(exc))
            except Exception:
                logger.exception("Không thể ghi nhận lỗi cho scan job %s", session_id)
        finally:
            _scan_queue.task_done()


def _ensure_worker() -> None:
    """Khởi chạy đúng một daemon worker cho process hiện tại."""
    global _worker_thread
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(
                target=_worker_loop,
                name="scan-task-worker",
                daemon=True,
            )
            _worker_thread.start()


def submit(session_id: int) -> None:
    """Đưa session ID vào hàng đợi; hàm trả về ngay, không chạy scan đồng bộ."""
    _ensure_worker()
    _scan_queue.put(session_id)