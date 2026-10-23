"""
Thực thể ORM quản lý người dùng và phân quyền truy cập hệ thống (User Model).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash

from models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """Bảng lưu thông tin tài khoản người dùng quản trị/kiểm thử viên."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="pentester", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def set_password(self, raw_password: str) -> None:
        """Băm mật khẩu an toàn trước khi lưu."""
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Kiểm tra mật khẩu người dùng nhập vào."""
        return check_password_hash(self.password_hash, raw_password)

    def to_dict(self) -> dict[str, Any]:
        """Chuyển đổi thông tin người dùng sang dictionary (ẩn password_hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
