"""
Ghi chú kiến trúc hàng đợi nền (Single-Process Queue vs Celery):

Dự án hiện tại triển khai hàng đợi tác vụ quét bằng `queue.Queue` kết hợp một daemon worker thread
trong cùng process (`tasks/scan_tasks.py`) và cơ chế khôi phục phiên dang dở khi khởi động
(`tasks/recovery_tasks.py`). Do bộ đếm rate-limit, hàng đợi quét và tín hiệu dừng (`threading.Event`)
lưu trong bộ nhớ của một process duy nhất, hệ thống cưỡng bức `WORKER_PROCESSES=1` tại `config/config.py`.

Tệp này được giữ lại để đối chiếu cấu trúc với `Docs/owasp_scanner_web_fake.txt` mà không tạo
hệ thống Celery/Redis thứ hai chạy song song.
"""

from __future__ import annotations

CELERY_ENABLED: bool = False
WORKER_BACKEND: str = "in_memory_queue_single_process"
