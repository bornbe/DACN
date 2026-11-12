"""
Kiểm thử dừng phiên quét an toàn (Graceful Cancel) trong vòng lặp Engine/Worker - Yêu cầu #3.
Xác minh khi gửi tín hiệu dừng (`stop_scan`), vòng lặp quét dừng ngay lập tức và trạng thái
cuối cùng trong CSDL là `CANCELLED`, không bị ghi đè thành `COMPLETED`.
"""

from __future__ import annotations

import threading

from core.crawler.bfs_crawler import CrawlResult
from core.crawler.form_parser import EndpointDescriptor
from core.scanners.base_scanner import BaseScanner, Finding
from models.base import Base, get_session_factory, init_db
from models.scan_job import ScanStatus
from models.user import User
from services import scan_service


def test_graceful_cancel_halts_engine_loop_and_persists_cancelled():
    engine = init_db("sqlite:///:memory:")
    factory = get_session_factory(engine)
    scan_service.configure_worker_session_factory(factory)

    scanning_started = threading.Event()
    stop_observed = threading.Event()
    scanned_urls: list[str] = []

    class ControlledScanner(BaseScanner):
        category = "headers"
        name = "controlled"

        def scan(self, endpoint: EndpointDescriptor) -> list[Finding]:
            scanned_urls.append(endpoint.url)
            scanning_started.set()
            if self.stop_event is not None and self.stop_event.wait(timeout=5):
                stop_observed.set()
            return []

    try:
        with factory() as db:
            user = User(username="cancel-user", email="cancel@example.test")
            user.set_password("StrongPass123!")
            db.add(user)
            db.commit()
            user_id = user.id
            scan = scan_service.create_scan(
                db,
                user_id=user_id,
                url="http://127.0.0.1:8080",
                max_depth=1,
                modules=["headers"],
            )
            session_id = scan.id

        endpoints = [
            EndpointDescriptor(url=f"http://127.0.0.1:8080/page-{i}", method="GET", params={"id": str(i)})
            for i in range(5)
        ]

        from unittest.mock import patch

        with (
            patch(
                "core.engine.scan_engine.BFSCrawler.crawl",
                return_value=CrawlResult(
                    base_url="http://127.0.0.1:8080",
                    visited_urls=["http://127.0.0.1:8080/"],
                    endpoints=endpoints,
                ),
            ),
            patch("core.engine.scan_engine.load_scanner_class", return_value=ControlledScanner),
        ):
            worker = threading.Thread(target=scan_service.run_scan, args=(session_id,))
            worker.start()

            assert scanning_started.wait(timeout=5)
            with factory() as db:
                res = scan_service.stop_scan(db, session_id, user_id)
                assert res is not None
                assert res["state"] == "cancelling"

            assert stop_observed.wait(timeout=5)
            worker.join(timeout=5)
            assert not worker.is_alive()

        # Chỉ mới quét endpoint đầu tiên trước khi dừng, không chạy tiếp các endpoint còn lại
        assert len(scanned_urls) == 1

        with factory() as db:
            final_scan = scan_service.get_scan(db, session_id, user_id)
            assert final_scan is not None
            assert final_scan.status == ScanStatus.CANCELLED.value
            assert final_scan.end_time is not None
    finally:
        Base.metadata.drop_all(bind=engine)
