"""
Ghi chú kiến trúc Worker (`tasks/celery_app.py`):

Hệ thống sử dụng hàng đợi nội bộ `tasks/scan_tasks.py` (`queue.Queue` + daemon worker thread)
và `tasks/recovery_tasks.py` trong mô hình single-process (`WORKER_PROCESSES=1`), không sử dụng
Celery/Redis broker để tránh phát sinh hai cơ chế điều phối bất đồng bộ song song.
"""

from __future__ import annotations

from config.celery_config import CELERY_ENABLED, WORKER_BACKEND

__all__ = ["CELERY_ENABLED", "WORKER_BACKEND"]
