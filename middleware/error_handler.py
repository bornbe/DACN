"""
Chuẩn hóa lỗi HTTP/API thành JSON - Issue #5.1/#5.2.
"""

from __future__ import annotations

import logging

from flask import Flask, jsonify
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


def register_error_handlers(app: Flask) -> None:
    """Đăng ký phản hồi JSON cho lỗi HTTP và lỗi server không dự kiến."""
    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> ResponseReturnValue:
        return jsonify(error=error.name, message=error.description), error.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> ResponseReturnValue:
        logger.exception("Lỗi không xử lý được trong Web API")
        return jsonify(error="Internal Server Error", message="Đã xảy ra lỗi nội bộ."), 500