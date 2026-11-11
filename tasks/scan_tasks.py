"""
Hàng đợi scan nền bằng queue.Queue và một worker thread (single-process) - Issue #5.2.
"""

from __future__ import annotations

import logging
import queue
import threading

from services.scan_service import is_scan_running, mark_scan_failed, run_scan

logger = logging.getLogger(__name__)
_scan_queue: queue.Queue[int] = queue.Queue()
_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_queued_or_active: set[int] = set()


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
            with _worker_lock:
                _queued_or_active.discard(session_id)
            _scan_queue.task_done()


def _ensure_worker() -> None:
    """Khởi chạy đúng một daemon worker cho process hiện tại (yêu cầu giữ _worker_lock)."""
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(
            target=_worker_loop,
            name="scan-task-worker",
            daemon=True,
        )
        _worker_thread.start()


def is_queued_or_running(session_id: int) -> bool:
    """Kiểm tra phiên quét đã nằm trong hàng đợi hoặc đang được worker xử lý hay chưa."""
    with _worker_lock:
        if session_id in _queued_or_active:
            return True
    return is_scan_running(session_id)


def submit(session_id: int) -> bool:
    """
    Đưa session ID vào hàng đợi nền nếu chưa có trong hàng đợi/worker.
    Trả True nếu job được thêm mới, False nếu bỏ qua do đã tồn tại.
    """
    with _worker_lock:
        if session_id in _queued_or_active or is_scan_running(session_id):
            return False
        _queued_or_active.add(session_id)
        _ensure_worker()
        _scan_queue.put(session_id)
        return True
