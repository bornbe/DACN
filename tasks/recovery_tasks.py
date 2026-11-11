"""
Khôi phục hàng đợi quét sau khi khởi động lại - Issue #5.2 (fix review).

Hàng đợi scan nằm trong RAM nên khi server restart/crash, các phiên đã được API lưu ở trạng thái
PENDING (hoặc đang RUNNING dang dở) sẽ bị "mồ côi". Module này quét lại các phiên đó và đưa
chúng vào lại hàng đợi để tiếp tục xử lý.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)


def recover_pending_scans(session_factory: sessionmaker[Session]) -> int:
    """
    Tìm các phiên quét còn dang dở (PENDING hoặc RUNNING) và đưa lại vào hàng đợi.
    Phiên RUNNING bị gián đoạn sẽ được đặt lại về PENDING (progress 0) trước khi chạy lại.
    Trả về số phiên đã đưa lại hàng đợi.
    """
    from models.scan_job import ScanSession, ScanStatus
    from tasks.scan_tasks import submit

    db = session_factory()
    try:
        interrupted = (
            db.query(ScanSession)
            .filter(
                ScanSession.status.in_(
                    [ScanStatus.PENDING.value, ScanStatus.RUNNING.value]
                )
            )
            .all()
        )
        session_ids: list[int] = []
        for scan in interrupted:
            if scan.status == ScanStatus.RUNNING.value:
                scan.status = ScanStatus.PENDING.value
                scan.progress = 0
            session_ids.append(scan.id)
        if interrupted:
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("Lỗi khi khôi phục danh sách phiên quét dang dở.")
        raise
    finally:
        db.close()

    for session_id in session_ids:
        submit(session_id)
    return len(session_ids)