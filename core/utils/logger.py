"""
Tiện ích ghi log dùng chung cho Scanner, Engine và CLI.
Tích hợp `mask_sensitive_data` vào Formatter để tự động ẩn thông tin nhạy cảm (token, cookie, password, JWT) trong log.
"""

from __future__ import annotations

import logging

from core.security.data_sanitizer import mask_sensitive_data

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


class SanitizingFormatter(logging.Formatter):
    """Formatter tự động che dữ liệu nhạy cảm trước khi xuất ra luồng log."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return mask_sensitive_data(rendered) or ""


def get_logger(name: str, level: int = logging.WARNING) -> logging.Logger:
    """
    Lấy logger theo tên module. Mặc định chỉ hiển thị WARNING trở lên để
    không làm nhiễu giao diện CLI (thanh tiến trình, bảng kết quả).
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(SanitizingFormatter(_LOG_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
