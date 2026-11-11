"""
Khôi phục hàng đợi quét sau khi khởi động lại - Issue #5.2 (fix review).

Hàng đợi scan nằm trong RAM của một process duy nhất nên khi server restart/crash, các phiên
đã được lưu ở trạng thái PENDING hoặc đang chạy dở (RUNNING/CRAWLING/SCANNING) sẽ bị mồ côi.
Module này quét lại các phiên đó, đưa các phiên đang chạy dở về PENDING (progress = 0) trong
một transaction nguyên tử và đưa vào hàng đợi để tiếp tục xử lý mà không enqueue trùng lặp.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
from weakref import WeakKeyDictionary

from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)
_recovery_lock = threading.Lock()
_recovered_by_engine: WeakKeyDictionary[Any, set[int]] = WeakKeyDictionary()
_fallback_recovered: set[int] = set()


def _get_recovered_set(session_factory: sessionmaker[Session]) -> set[int]:
    bind = session_factory.kw.get("bind") if hasattr(session_factory, "kw") else None
    if bind is not None:
        try:
            return _recovered_by_engine.setdefault(bind, set())
        except TypeError:
            pass
    return _fallback_recovered


def clear_recovered_scan(session_id: int) -> None:
    """Xóa đánh dấu recovery của phiên sau khi worker đã xử lý xong."""
    with _recovery_lock:
        _fallback_recovered.discard(session_id)
        for recovered_set in _recovered_by_engine.values():
            recovered_set.discard(session_id)


def recover_pending_scans(session_factory: sessionmaker[Session]) -> int:
    """
    Tìm các phiên quét còn dang dở (PENDING, RUNNING, CRAWLING, SCANNING) và đưa lại vào hàng đợi.
    - Phiên RUNNING/CRAWLING/SCANNING bị gián đoạn sẽ được đặt lại về PENDING (progress = 0).
    - Phiên COMPLETED/CANCELLED/FAILED/NO_MODULES không bao giờ bị khôi phục.
    - Không enqueue trùng nếu recover_pending_scans được gọi nhiều lần trong cùng process.
    Trả về số phiên thực sự được đưa lại vào hàng đợi.
    """
    from models.scan_job import ScanSession, ScanStatus
    from services.scan_service import ACTIVE_STATUSES, is_scan_running
    from tasks import scan_tasks

    recoverable_statuses = (
        ScanStatus.PENDING.value,
        ScanStatus.RUNNING.value,
        ScanStatus.CRAWLING.value,
        ScanStatus.SCANNING.value,
    )

    with _recovery_lock:
        recovered_set = _get_recovered_set(session_factory)
        db = session_factory()
        session_ids: list[int] = []
        try:
            interrupted = (
                db.query(ScanSession)
                .filter(ScanSession.status.in_(recoverable_statuses))
                .order_by(ScanSession.id.asc())
                .all()
            )
            for scan in interrupted:
                if (
                    scan.id in recovered_set
                    or is_scan_running(scan.id)
                    or scan_tasks.is_queued_or_running(scan.id)
                ):
                    continue
                if scan.status in ACTIVE_STATUSES:
                    scan.status = ScanStatus.PENDING.value
                    scan.progress = 0
                    scan.end_time = None
                session_ids.append(scan.id)
            if session_ids:
                db.commit()
        except Exception:
            db.rollback()
            logger.exception("Lỗi khi khôi phục danh sách phiên quét dang dở.")
            raise
        finally:
            db.close()

        enqueued = 0
        for session_id in session_ids:
            recovered_set.add(session_id)
            result = scan_tasks.submit(session_id)
            if result is not False:
                enqueued += 1
        return enqueued
