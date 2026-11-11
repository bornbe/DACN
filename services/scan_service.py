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

# Fix review (Critical #2): registry các phiên đang chạy -> cho phép endpoint /stop hủy giữa chừng.
_running_scans: dict[int, threading.Event] = {}
_running_lock = threading.Lock()


def _register_running_scan(session_id: int, stop_event: threading.Event) -> None:
    with _running_lock:
        _running_scans[session_id] = stop_event


def _unregister_running_scan(session_id: int) -> None:
    with _running_lock:
        _running_scans.pop(session_id, None)


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
    db = _new_worker_session()
    try:
        scan = db.get(ScanSession, session_id)
        if scan is None:
            raise LookupError(f"Không tìm thấy phiên quét {session_id}.")
        target_url = scan.target.url
        modules = list(scan.modules_enabled)
        max_depth = scan.max_depth
        # Fix review (Critical #2): nếu đã bị yêu cầu hủy lúc còn PENDING thì không chạy.
        if scan.status == ScanStatus.CANCELLED.value:
            scan.end_time = scan.end_time or datetime.now(timezone.utc)
            db.commit()
            cancelled_report = ScanReport()
            cancelled_report.status = ScanStatus.CANCELLED.value
            return cancelled_report
        scan.status = ScanStatus.RUNNING.value
        scan.start_time = datetime.now(timezone.utc)
        scan.error_message = None
        db.commit()

        def persist_event(event: dict[str, Any]) -> None:
            try:
                current = db.get(ScanSession, session_id)
                if current is None:
                    raise LookupError(f"Phiên quét {session_id} đã bị xóa.")
                if event.get("type") == "status" and isinstance(event.get("status"), str):
                    current.status = event["status"]
                if event.get("type") == "progress":
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
            user_id=scan.user_id,
            target_name=scan.target.name,
            on_event=persist_event,
        )
        # Đăng ký cờ dừng để endpoint /stop có thể hủy phiên đang chạy.
        _register_running_scan(session_id, context.stop_event)
        report = ScanEngine(context).run()
        scan = db.get(ScanSession, session_id)
        if scan is None:
            raise LookupError(f"Phiên quét {session_id} đã bị xóa.")
        _persist_results(db, scan, report)
        scan.status = report.status
        scan.progress = 100 if report.status == ScanStatus.COMPLETED.value else scan.progress
        scan.summary_stats = report.summary
        scan.error_message = report.error_message or report.message
        scan.end_time = report.end_time or datetime.now(timezone.utc)
        db.commit()
        return report
    except Exception as exc:
        db.rollback()
        failed = db.get(ScanSession, session_id)
        if failed is not None:
            failed.status = ScanStatus.FAILED.value
            failed.error_message = str(exc)
            failed.end_time = datetime.now(timezone.utc)
            db.commit()
        logger.exception("Worker thực thi phiên quét %s thất bại", session_id)
        raise
    finally:
        _unregister_running_scan(session_id)
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
    """Đưa phiên về FAILED nếu worker gặp lỗi ngoài dự kiến."""
    db = _new_worker_session()
    try:
        scan = db.get(ScanSession, session_id)
        if scan is not None:
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
    query = db.query(ScanSession).filter(ScanSession.id == session_id)
    if user_id is not None:
        query = query.filter(ScanSession.user_id == user_id)
    return query.first()


def stop_scan(db: Session, session_id: int, user_id: int) -> dict[str, Any] | None:
    """
    Yêu cầu dừng một phiên quét của người dùng (fix review Critical #2).
    - Phiên đã kết thúc (COMPLETED/FAILED/CANCELLED) -> báo already_finished.
    - Phiên RUNNING -> gửi tín hiệu hủy cho worker (engine chuyển sang CANCELLED).
    - Phiên PENDING (chưa chạy) -> đặt thẳng trạng thái CANCELLED.
    Trả None nếu không tìm thấy phiên hoặc phiên không thuộc người dùng.
    """
    scan = get_scan(db, session_id, user_id)
    if scan is None:
        return None
    finished = {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}
    if scan.status in finished:
        return {"state": "already_finished", "status": scan.status}
    if scan.status == ScanStatus.RUNNING.value:
        request_stop(session_id)
        return {"state": "cancelling", "status": scan.status}
    scan.status = ScanStatus.CANCELLED.value
    scan.end_time = datetime.now(timezone.utc)
    db.commit()
    return {"state": "cancelled", "status": ScanStatus.CANCELLED.value}


def list_scans(db: Session, user_id: int, limit: int = 100) -> list[ScanSession]:
    """Liệt kê tối đa 100 phiên gần nhất của người dùng."""
    return (
        db.query(ScanSession)
        .filter(ScanSession.user_id == user_id)
        .order_by(ScanSession.id.desc())
        .limit(limit)
        .all()
    )


def list_findings(db: Session, session_id: int, user_id: int | None = None) -> list[VulnerabilityFinding]:
    """Liệt kê finding nếu phiên thuộc người dùng yêu cầu."""
    query = db.query(VulnerabilityFinding).join(ScanSession).filter(
        VulnerabilityFinding.session_id == session_id
    )
    if user_id is not None:
        query = query.filter(ScanSession.user_id == user_id)
    return query.order_by(VulnerabilityFinding.id.asc()).all()