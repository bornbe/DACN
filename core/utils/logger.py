"""
Tiện ích ghi log dùng chung cho Scanner, Engine và CLI.
"""

from __future__ import annotations

import logging

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def get_logger(name: str, level: int = logging.WARNING) -> logging.Logger:
    """
    Lấy logger theo tên module. Mặc định chỉ hiển thị WARNING trở lên để
    không làm nhiễu giao diện CLI (thanh tiến trình, bảng kết quả).
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
