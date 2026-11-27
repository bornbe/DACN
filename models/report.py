"""
Thực thể ORM quản lý lịch sử xuất báo cáo kỹ thuật (Report).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin


class Report(Base, TimestampMixin):
    """Bảng lưu thông tin các lần kết xuất báo cáo kiểm thử."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    report_format: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "report_format": self.report_format,
            "file_path": self.file_path,
            "generated_at": self.created_at.isoformat() if self.created_at else None,
        }
