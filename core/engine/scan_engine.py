"""
Bộ điều phối trung tâm (Engine Orchestrator) - Issue #4.1.
Luồng: nhận mục tiêu + cấu hình -> BFSCrawler -> danh sách endpoint -> đẩy qua các Scanner
-> lọc trùng Finding -> lưu CSDL (mã hóa At-Rest) -> báo tiến độ qua Event Callback.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from core.crawler.bfs_crawler import BFSCrawler
from core.crawler.form_parser import EndpointDescriptor
from core.engine.result_manager import ResultManager
from core.engine.scan_context import ScanCancelled, ScanContext
from core.scanners import ALL_MODULES, BaseScanner, Finding, load_scanner_class
from core.utils.logger import get_logger

logger = get_logger(__name__)

# Tỷ trọng tiến độ: giai đoạn crawl chiếm 0-40%, giai đoạn scan 40-100%
CRAWL_PROGRESS_SHARE = 40


@dataclass
class ScanReport:
    """Kết quả tổng hợp của một phiên quét."""

    target_url: str
    status: str = "PENDING"
    session_id: int | None = None
    modules: list[str] = field(default_factory=list)
    skipped_modules: dict[str, str] = field(default_factory=dict)
    start_time: datetime | None = None
    end_time: datetime | None = None
    endpoints: list[EndpointDescriptor] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return round((self.end_time - self.start_time).total_seconds(), 2)
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status": self.status,
            "session_id": self.session_id,
            "modules": self.modules,
            "skipped_modules": self.skipped_modules,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "summary": self.summary,
            "error_message": self.error_message,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "findings": [f.to_dict() for f in self.findings],
        }


def normalize_modules(modules: list[str] | None) -> list[str]:
    """Chuẩn hóa danh sách module: 'all' hoặc rỗng -> toàn bộ; loại trùng, giữ thứ tự."""
    if not modules:
        return list(ALL_MODULES)
    cleaned: list[str] = []
    for m in modules:
        key = m.strip().lower()
        if key == "all":
            return list(ALL_MODULES)
        if key and key not in cleaned:
            cleaned.append(key)
    return cleaned


class ScanEngine:
    """Điều phối một phiên quét từ đầu đến cuối."""

    def __init__(self, context: ScanContext, db_session: Session | None = None) -> None:
        self.ctx = context
        self.db = db_session
        self.results = ResultManager()
        self._session_id: int | None = None
        self._last_percent = -1

    # ------------------------------------------------------------------ public
    def run(self) -> ScanReport:
        ctx = self.ctx
        report = ScanReport(
            target_url=ctx.target_url,
            modules=normalize_modules(ctx.modules),
            start_time=datetime.now(timezone.utc),
        )
        pages_crawled = 0
        try:
            self._validate_target(ctx.target_url)
            self._init_persistence(report)

            # Giai đoạn 1: Crawl
            self._set_status(report, "CRAWLING")
            crawl_result = self._crawl()
            pages_crawled = len(crawl_result.visited_urls)
            report.endpoints = self._with_root_endpoint(crawl_result.endpoints)
            if self.db is not None and self._session_id:
                ResultManager.persist_endpoints(self.db, self._session_id, report.endpoints)

            # Giai đoạn 2: Scan
            self._set_status(report, "SCANNING")
            scanners = self._build_scanners(report)
            self._scan(report.endpoints, scanners)

            report.status = "COMPLETED"
        except (ScanCancelled, KeyboardInterrupt):
            report.status = "CANCELLED"
            report.error_message = "Phiên quét đã bị hủy."
            ctx.stop_event.set()
        except Exception as exc:  # noqa: BLE001 - mọi lỗi đều phải được ghi nhận vào báo cáo
            logger.exception("Phiên quét thất bại")
            report.status = "FAILED"
            report.error_message = str(exc)
        finally:
            report.end_time = datetime.now(timezone.utc)
            report.findings = self.results.findings
            report.summary = self.results.build_summary(len(report.endpoints), pages_crawled)
            self._finalize_persistence(report)
            if report.status == "COMPLETED":
                self._progress(100, "DONE", "Hoàn tất quét.")
            ctx.emit("status", status=report.status)
        return report

    # ------------------------------------------------------------------ steps
    @staticmethod
    def _validate_target(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"URL mục tiêu không hợp lệ (cần http:// hoặc https://): {url}")

    def _crawl(self) -> Any:
        ctx = self.ctx

        def on_progress(pages: int, url: str) -> None:
            ctx.check_cancelled()
            percent = int(min(pages / max(ctx.max_pages, 1), 1.0) * CRAWL_PROGRESS_SHARE)
            self._progress(percent, "CRAWLING", f"Crawl [{pages}/{ctx.max_pages}] {url}")

        crawler = BFSCrawler(
            base_url=ctx.target_url,
            max_depth=ctx.max_depth,
            max_pages=ctx.max_pages,
            timeout=ctx.timeout,
            on_progress=on_progress,
        )
        return crawler.crawl()

    def _with_root_endpoint(self, endpoints: list[EndpointDescriptor]) -> list[EndpointDescriptor]:
        """Luôn đưa trang gốc vào danh sách để các scanner cấp site (Headers) có điểm khởi đầu."""
        root = EndpointDescriptor(url=self.ctx.target_url, method="GET", params={}, source="root", depth=0)
        if any(ep.signature() == root.signature() for ep in endpoints):
            return list(endpoints)
        return [root, *endpoints]

    def _build_scanners(self, report: ScanReport) -> list[BaseScanner]:
        """Khởi tạo scanner theo module được chọn; module chưa sẵn sàng bị bỏ qua kèm cảnh báo."""
        ctx = self.ctx
        scanners: list[BaseScanner] = []
        active: list[str] = []
        for key in report.modules:
            try:
                scanner_cls = load_scanner_class(key)
                scanners.append(
                    scanner_cls(
                        timeout=ctx.timeout,
                        request_delay=ctx.request_delay,
                        stop_event=ctx.stop_event,
                    )
                )
                active.append(key)
            except (ImportError, LookupError, KeyError, TypeError) as exc:
                reason = f"{type(exc).__name__}: {exc}"
                report.skipped_modules[key] = reason
                ctx.emit("warning", message=f"Bỏ qua module '{key}': {reason}")
        report.modules = active
        if not scanners:
            raise RuntimeError("Không có module quét khả dụng nào để thực thi.")
        return scanners

    def _scan(self, endpoints: list[EndpointDescriptor], scanners: list[BaseScanner]) -> None:
        ctx = self.ctx
        total_steps = max(len(endpoints) * len(scanners), 1)
        done = 0
        for endpoint in endpoints:
            for scanner in scanners:
                ctx.check_cancelled()
                for finding in scanner.safe_scan(endpoint):
                    if self.results.add(finding):
                        ctx.emit("finding", finding=finding.to_dict())
                done += 1
                percent = CRAWL_PROGRESS_SHARE + int(done / total_steps * (100 - CRAWL_PROGRESS_SHARE))
                self._progress(
                    min(percent, 99),
                    "SCANNING",
                    f"[{scanner.name}] {endpoint.method} {endpoint.url}",
                )

    # ------------------------------------------------------------------ events
    def _progress(self, percent: int, phase: str, message: str) -> None:
        self.ctx.emit("progress", percent=percent, phase=phase, message=message)
        if percent != self._last_percent:
            self._last_percent = percent
            self._db_update(progress=percent)

    def _set_status(self, report: ScanReport, status: str) -> None:
        report.status = status
        self._db_update(status=status)
        self.ctx.emit("status", status=status)

    # ------------------------------------------------------------------ persistence
    def _init_persistence(self, report: ScanReport) -> None:
        if self.db is None:
            return
        from models.scan_job import ScanSession, ScanStatus, ScanTarget

        try:
            target = self.db.query(ScanTarget).filter(ScanTarget.url == self.ctx.target_url).first()
            if target is None:
                target = ScanTarget(
                    name=self.ctx.target_name or urlparse(self.ctx.target_url).netloc,
                    url=self.ctx.target_url,
                )
                self.db.add(target)
                self.db.flush()
            session = ScanSession(
                target_id=target.id,
                user_id=self.ctx.user_id,
                status=ScanStatus.PENDING.value,
                max_depth=self.ctx.max_depth,
                modules_enabled=report.modules,
                start_time=report.start_time,
            )
            self.db.add(session)
            self.db.commit()
            self._session_id = session.id
            report.session_id = session.id
        except Exception as exc:  # noqa: BLE001 - lỗi CSDL không được chặn việc quét
            self.db.rollback()
            self.db = None
            self.ctx.emit("warning", message=f"Không thể lưu vào CSDL, quét ở chế độ không lưu: {exc}")

    def _db_update(self, **fields: Any) -> None:
        if self.db is None or self._session_id is None:
            return
        from models.scan_job import ScanSession

        try:
            self.db.query(ScanSession).filter(ScanSession.id == self._session_id).update(fields)
            self.db.commit()
        except Exception as exc:  # noqa: BLE001
            self.db.rollback()
            logger.warning("Cập nhật phiên quét thất bại: %s", exc)

    def _finalize_persistence(self, report: ScanReport) -> None:
        if self.db is None or self._session_id is None:
            return
        try:
            self.results.persist_findings(self.db, self._session_id)
        except Exception as exc:  # noqa: BLE001
            self.db.rollback()
            self.ctx.emit("warning", message=f"Lưu findings thất bại: {exc}")
        self._db_update(
            status=report.status,
            progress=100 if report.status == "COMPLETED" else max(self._last_percent, 0),
            end_time=report.end_time,
            summary_stats=report.summary,
            error_message=report.error_message,
        )
