"""
Dịch vụ tạo, thực thi và truy vấn phiên quét - Issue #5.1/#5.2.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session, sessionmaker

from core.engine.scan_context import ScanContext
from core.engine.scan_engine import ScanEngine, ScanReport
from core.scanners.base_scanner import Finding
from models.base import get_session_factory
from models.scan_job import CrawledEndpoint, ScanSession, ScanStatus, ScanTarget
from models.vulnerability import VulnerabilityFinding

logger = logging.getLogger(__name__)
_worker_session_factory: sessionmaker[Session] | None = None

ACTIVE_STATUSES: frozenset[str] = frozenset(
    {
        ScanStatus.RUNNING.value,
        ScanStatus.CRAWLING.value,
        ScanStatus.SCANNING.value,
    }
)
FINISHED_STATUSES: frozenset[str] = frozenset(
    {
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
        ScanStatus.NO_MODULES.value,
    }
)
CANCELLED_MESSAGE = "Phiên quét đã bị hủy."

# Registry các phiên đang chạy -> cho phép endpoint /stop hủy giữa chừng ở RUNNING/CRAWLING/SCANNING.
# Mỗi phiên có một threading.Event riêng biệt, tuyệt đối không dùng chung giữa các phiên.
_running_scans: dict[int, threading.Event] = {}
_running_lock = threading.Lock()
# Khóa bảo vệ các thao tác DB ngắn hạn khi nhiều luồng dùng chung kết nối SQLite (StaticPool).
_db_lock = threading.RLock()


def _try_register_running_scan(session_id: int, stop_event: threading.Event) -> bool:
    """Đăng ký stop_event riêng cho phiên nếu chưa có worker khác đang chạy cùng session_id."""
    with _running_lock:
        if session_id in _running_scans:
            return False
        _running_scans[session_id] = stop_event
        return True


def _register_running_scan(session_id: int, stop_event: threading.Event) -> None:
    with _running_lock:
        _running_scans[session_id] = stop_event


def _unregister_running_scan(session_id: int, expected_event: threading.Event | None = None) -> None:
    with _running_lock:
        if expected_event is None or _running_scans.get(session_id) is expected_event:
            _running_scans.pop(session_id, None)


def is_scan_running(session_id: int) -> bool:
    """Kiểm tra phiên quét có đang được worker thực thi trong process hiện tại không."""
    with _running_lock:
        return session_id in _running_scans


def request_stop(session_id: int) -> bool:
    """Gửi tín hiệu hủy tới phiên đang chạy (nếu có). Trả True nếu phiên đang chạy thật."""
    with _running_lock:
        stop_event = _running_scans.get(session_id)
    if stop_event is not None:
        stop_event.set()
        return True
    return False


def configure_worker_session_factory(session_factory: sessionmaker[Session]) -> None:
    """Gắn sessionmaker của ứng dụng để worker dùng cùng database nhưng session riêng."""
    global _worker_session_factory
    _worker_session_factory = session_factory


def _new_worker_session() -> Session:
    factory = _worker_session_factory if _worker_session_factory is not None else get_session_factory()
    return factory()


def create_scan(
    db: Session,
    user_id: int,
    url: str,
    max_depth: int,
    modules: list[str],
) -> ScanSession:
    """Tạo target và phiên PENDING trong transaction của request."""
    with _db_lock:
        hostname = urlsplit(url).hostname or url
        target = ScanTarget(name=hostname[:150], url=url, description="Authorized local lab target")
        db.add(target)
        db.flush()
        scan = ScanSession(
            target_id=target.id,
            user_id=user_id,
            status=ScanStatus.PENDING.value,
            progress=0,
            max_depth=max_depth,
            modules_enabled=modules,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan


def run_scan(session_id: int) -> ScanReport:
    """Chạy engine bằng session DB riêng của worker và lưu kết quả vào phiên đã tạo."""
    from tasks.recovery_tasks import clear_recovered_scan

    stop_event = threading.Event()
    registered = _try_register_running_scan(session_id, stop_event)
    db = _new_worker_session()
    try:
        with _db_lock:
            scan = db.get(ScanSession, session_id)
            if scan is None:
                raise LookupError(f"Không tìm thấy phiên quét {session_id}.")
            target_url = scan.target.url
            modules = list(scan.modules_enabled)
            max_depth = scan.max_depth
            user_id = scan.user_id
            target_name = scan.target.name

            # Nếu worker khác trong cùng process đang chạy phiên này thì không chạy trùng.
            if not registered:
                return ScanReport(
                    target_url=target_url,
                    status=scan.status,
                    session_id=session_id,
                    modules=modules,
                    start_time=scan.start_time,
                    end_time=scan.end_time,
                    error_message=scan.error_message,
                )

            # Nếu đã bị yêu cầu hủy lúc còn PENDING thì không chạy.
            if scan.status == ScanStatus.CANCELLED.value:
                scan.end_time = scan.end_time or datetime.now(timezone.utc)
                scan.error_message = scan.error_message or CANCELLED_MESSAGE
                db.commit()
                return ScanReport(
                    target_url=target_url,
                    status=ScanStatus.CANCELLED.value,
                    session_id=session_id,
                    modules=modules,
                    start_time=scan.start_time,
                    end_time=scan.end_time,
                    error_message=scan.error_message,
                )

            # Claim nguyên tử từ PENDING -> RUNNING để chống race condition với /stop và chống chạy trùng.
            now = datetime.now(timezone.utc)
            claimed = (
                db.query(ScanSession)
                .filter(
                    ScanSession.id == session_id,
                    ScanSession.status == ScanStatus.PENDING.value,
                )
                .update(
                    {
                        ScanSession.status: ScanStatus.RUNNING.value,
                        ScanSession.start_time: now,
                        ScanSession.error_message: None,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            db.expire_all()
            scan = db.get(ScanSession, session_id)
            if scan is None:
                raise LookupError(f"Phiên quét {session_id} đã bị xóa.")

            if claimed == 0:
                if scan.status == ScanStatus.CANCELLED.value:
                    scan.end_time = scan.end_time or datetime.now(timezone.utc)
                    scan.error_message = scan.error_message or CANCELLED_MESSAGE
                    db.commit()
                return ScanReport(
                    target_url=target_url,
                    status=scan.status,
                    session_id=session_id,
                    modules=modules,
                    start_time=scan.start_time,
                    end_time=scan.end_time,
                    error_message=scan.error_message,
                )

        def persist_event(event: dict[str, Any]) -> None:
            with _db_lock:
                try:
                    db.expire_all()
                    current = db.get(ScanSession, session_id)
                    if current is None:
                        raise LookupError(f"Phiên quét {session_id} đã bị xóa.")
                    if current.status == ScanStatus.CANCELLED.value:
                        stop_event.set()
                        return
                    if event.get("type") == "status" and isinstance(event.get("status"), str):
                        new_status = event["status"]
                        if stop_event.is_set() and new_status != ScanStatus.CANCELLED.value:
                            return
                        current.status = new_status
                    if event.get("type") == "progress":
                        if stop_event.is_set():
                            return
                        percent = event.get("percent")
                        if isinstance(percent, int) and not isinstance(percent, bool):
                            current.progress = min(max(percent, 0), 100)
                    db.commit()
                except Exception:
                    db.rollback()
                    logger.exception("Không thể cập nhật tiến độ phiên quét %s", session_id)
                    raise

        context = ScanContext(
            target_url=target_url,
            max_depth=max_depth,
            modules=modules,
            persist=False,
            user_id=user_id,
            target_name=target_name,
            on_event=persist_event,
            stop_event=stop_event,
        )
        report = ScanEngine(context).run()

        with _db_lock:
            db.expire_all()
            scan = db.get(ScanSession, session_id)
            if scan is None:
                raise LookupError(f"Phiên quét {session_id} đã bị xóa.")

            # Đảm bảo không bao giờ ghi đè thành COMPLETED nếu đã có tín hiệu dừng hoặc DB đã CANCELLED.
            if stop_event.is_set() or scan.status == ScanStatus.CANCELLED.value:
                report.status = ScanStatus.CANCELLED.value
                if not report.error_message:
                    report.error_message = scan.error_message or CANCELLED_MESSAGE

            _persist_results(db, scan, report)
            scan.status = report.status
            if report.status == ScanStatus.COMPLETED.value:
                scan.progress = 100
            scan.summary_stats = report.summary
            scan.error_message = report.error_message or report.message
            scan.end_time = report.end_time or scan.end_time or datetime.now(timezone.utc)
            db.commit()
            return report
    except Exception as exc:
        with _db_lock:
            db.rollback()
            db.expire_all()
            failed = db.get(ScanSession, session_id)
            if failed is not None:
                if stop_event.is_set() or failed.status == ScanStatus.CANCELLED.value:
                    failed.status = ScanStatus.CANCELLED.value
                    failed.error_message = failed.error_message or CANCELLED_MESSAGE
                else:
                    failed.status = ScanStatus.FAILED.value
                    failed.error_message = str(exc)
                failed.end_time = failed.end_time or datetime.now(timezone.utc)
                db.commit()
        logger.exception("Worker thực thi phiên quét %s thất bại", session_id)
        raise
    finally:
        if registered:
            _unregister_running_scan(session_id, stop_event)
            clear_recovered_scan(session_id)
        with _db_lock:
            db.close()


def _persist_results(db: Session, scan: ScanSession, report: ScanReport) -> None:
    """Lưu endpoint, finding và thống kê của báo cáo vào phiên hiện có."""
    for endpoint in report.endpoints:
        db.add(
            CrawledEndpoint(
                session_id=scan.id,
                url=endpoint.url,
                method=endpoint.method,
                depth=endpoint.depth,
                params_schema=endpoint.params_schema,
            )
        )
    for finding in report.findings:
        _persist_finding(db, scan.id, finding)


def _persist_finding(db: Session, session_id: int, finding: Finding) -> None:
    db.add(
        VulnerabilityFinding(
            session_id=session_id,
            vuln_type=finding.vuln_name,
            severity=finding.severity,
            target_url=finding.target_url,
            param=finding.parameter,
            payload=finding.payload,
            evidence=finding.evidence,
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            remediation=finding.remediation,
        )
    )


def mark_scan_failed(session_id: int, message: str) -> None:
    """Đưa phiên về FAILED nếu worker gặp lỗi ngoài dự kiến (không ghi đè phiên đã CANCELLED)."""
    with _db_lock:
        db = _new_worker_session()
        try:
            scan = db.get(ScanSession, session_id)
            if scan is not None and scan.status != ScanStatus.CANCELLED.value:
                scan.status = ScanStatus.FAILED.value
                scan.error_message = message
                scan.end_time = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
            logger.exception("Không thể cập nhật trạng thái FAILED cho phiên %s", session_id)
            raise
        finally:
            db.close()


def get_scan(db: Session, session_id: int, user_id: int | None = None) -> ScanSession | None:
    """Lấy phiên quét; có thể giới hạn theo chủ sở hữu."""
    with _db_lock:
        query = db.query(ScanSession).filter(ScanSession.id == session_id)
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        return query.first()


def stop_scan(db: Session, session_id: int, user_id: int) -> dict[str, Any] | None:
    """
    Yêu cầu dừng một phiên quét của người dùng:
    - Phiên đã kết thúc (COMPLETED/FAILED/CANCELLED/NO_MODULES) -> báo already_finished.
    - Phiên PENDING (chưa được worker lấy) -> cập nhật có điều kiện sang CANCELLED.
    - Phiên đang hoạt động (RUNNING/CRAWLING/SCANNING) -> gửi stop signal tới ScanContext.stop_event.
    Trả None nếu không tìm thấy phiên hoặc phiên không thuộc người dùng.
    """
    with _db_lock:
        scan = get_scan(db, session_id, user_id)
        if scan is None:
            return None
        db.refresh(scan)

        if scan.status in FINISHED_STATUSES:
            return {"state": "already_finished", "status": scan.status}

        if scan.status == ScanStatus.PENDING.value:
            now = datetime.now(timezone.utc)
            updated = (
                db.query(ScanSession)
                .filter(
                    ScanSession.id == session_id,
                    ScanSession.user_id == user_id,
                    ScanSession.status == ScanStatus.PENDING.value,
                )
                .update(
                    {
                        ScanSession.status: ScanStatus.CANCELLED.value,
                        ScanSession.end_time: now,
                        ScanSession.error_message: CANCELLED_MESSAGE,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            if updated == 1:
                request_stop(session_id)
                db.refresh(scan)
                return {"state": "cancelled", "status": ScanStatus.CANCELLED.value}
            db.refresh(scan)
            if scan.status in FINISHED_STATUSES:
                return {"state": "already_finished", "status": scan.status}

        if scan.status in ACTIVE_STATUSES:
            if request_stop(session_id):
                return {"state": "cancelling", "status": scan.status}
            db.refresh(scan)
            if scan.status in FINISHED_STATUSES:
                return {"state": "already_finished", "status": scan.status}
            now = datetime.now(timezone.utc)
            updated = (
                db.query(ScanSession)
                .filter(
                    ScanSession.id == session_id,
                    ScanSession.user_id == user_id,
                    ScanSession.status.in_(ACTIVE_STATUSES),
                )
                .update(
                    {
                        ScanSession.status: ScanStatus.CANCELLED.value,
                        ScanSession.end_time: now,
                        ScanSession.error_message: CANCELLED_MESSAGE,
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            db.refresh(scan)
            if updated == 1:
                return {"state": "cancelled", "status": ScanStatus.CANCELLED.value}
            return {"state": "already_finished", "status": scan.status}

        return {"state": "already_finished", "status": scan.status}


def list_scans(db: Session, user_id: int, limit: int = 100) -> list[ScanSession]:
    """Liệt kê tối đa 100 phiên gần nhất của người dùng."""
    with _db_lock:
        return (
            db.query(ScanSession)
            .filter(ScanSession.user_id == user_id)
            .order_by(ScanSession.id.desc())
            .limit(limit)
            .all()
        )


def list_findings(db: Session, session_id: int, user_id: int | None = None) -> list[VulnerabilityFinding]:
    """Liệt kê finding nếu phiên thuộc người dùng yêu cầu."""
    with _db_lock:
        query = db.query(VulnerabilityFinding).join(ScanSession).filter(
            VulnerabilityFinding.session_id == session_id
        )
        if user_id is not None:
            query = query.filter(ScanSession.user_id == user_id)
        return query.order_by(VulnerabilityFinding.id.asc()).all()
