"""
Kiểm tra dữ liệu đăng nhập/đăng ký - Issue #5.1.
"""

from __future__ import annotations

import re
from typing import Any

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_login(data: Any) -> dict[str, str]:
    """Kiểm tra payload đăng nhập và trả về dữ liệu đã chuẩn hóa."""
    if not isinstance(data, dict):
        raise ValueError("JSON body phải là một object.")
    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not username.strip():
        raise ValueError("username là bắt buộc.")
    if not isinstance(password, str) or not password:
        raise ValueError("password là bắt buộc.")
    return {"username": username.strip().lower(), "password": password}


def validate_register(data: Any) -> dict[str, str]:
    """Kiểm tra payload đăng ký; role không được nhận từ client."""
    if not isinstance(data, dict):
        raise ValueError("JSON body phải là một object.")
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    if not isinstance(username, str) or not 3 <= len(username.strip()) <= 80:
        raise ValueError("username phải có từ 3 đến 80 ký tự.")
    normalized_email = email.strip().lower() if isinstance(email, str) else ""
    if len(normalized_email) > 120 or not EMAIL_PATTERN.fullmatch(normalized_email):
        raise ValueError("email không hợp lệ.")
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("password phải có ít nhất 8 ký tự.")
    return {
        "username": username.strip().lower(),
        "email": normalized_email,
        "password": password,
    }