"""
Kiểm thử tính Idempotency của hàng đợi và worker single-process - Yêu cầu #3.
Xác minh khi gửi trùng lặp cùng một `session_id` vào hàng đợi hoặc gọi `run_scan` đồng thời,
chỉ có duy nhất 1 luồng thực thi `ScanEngine.run()`.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from unittest.mock import patch

from core.engine.scan_engine import ScanReport
from models.base import Base, get_session_factory, init_db
from models.user import User
from services import scan_service
from tasks import scan_tasks


def test_worker_idempotency_under_concurrent_submissions_and_execution():
    engine = init_db("sqlite:///:memory:")
    factory = get_session_factory(engine)
    scan_service.configure_worker_session_factory(factory)

    try:
        with factory() as db:
            user = User(username="idem-user", email="idem@example.test")
            user.set_password("StrongPass123!")
            db.add(user)
            db.commit()
            scan = scan_service.create_scan(
                db,
                user_id=user.id,
                url="http://127.0.0.1:8080",
                max_depth=1,
                modules=["headers"],
            )
            session_id = scan.id

        # 1. Kiểm tra deduplication tại hàng đợi submit()
        with patch.object(scan_tasks, "_ensure_worker"):
            first = scan_tasks.submit(session_id)
            second = scan_tasks.submit(session_id)
            third = scan_tasks.submit(session_id)
            assert first is True
            assert second is False
            assert third is False
            # Dọn trạng thái hàng đợi giả lập
            while not scan_tasks._scan_queue.empty():
                scan_tasks._scan_queue.get_nowait()
                scan_tasks._scan_queue.task_done()
            scan_tasks._queued_or_active.discard(session_id)

        # 2. Kiểm tra 3 worker thread cùng gọi run_scan(session_id) đồng thời:
        # chỉ có duy nhất 1 luồng thực sự chạy ScanEngine.run().
        barrier = threading.Barrier(3)
        engine_entered = threading.Event()
        release_engine = threading.Event()
        execution_count = 0
        count_lock = threading.Lock()

        def fake_engine_run(self):
            nonlocal execution_count
            with count_lock:
                execution_count += 1
            engine_entered.set()
            release_engine.wait(timeout=5)
            now = datetime.now(timezone.utc)
            return ScanReport(
                target_url=self.ctx.target_url,
                status="COMPLETED",
                modules=self.ctx.modules,
                start_time=now,
                end_time=now,
                summary={
                    "pages_crawled": 1,
                    "total_endpoints": 1,
                    "total_findings": 0,
                    "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                },
            )

        results: list[ScanReport] = []

        def worker_call():
            barrier.wait(timeout=5)
            results.append(scan_service.run_scan(session_id))

        with patch("core.engine.scan_engine.ScanEngine.run", new=fake_engine_run):
            threads = [threading.Thread(target=worker_call) for _ in range(3)]
            for t in threads:
                t.start()
            assert engine_entered.wait(timeout=5)
            release_engine.set()
            for t in threads:
                t.join(timeout=5)

        assert execution_count == 1
        assert len(results) == 3
        with factory() as db:
            final_scan = scan_service.get_scan(db, session_id, user.id)
            assert final_scan is not None
            assert final_scan.status == "COMPLETED"
            assert final_scan.progress == 100
    finally:
        Base.metadata.drop_all(bind=engine)
