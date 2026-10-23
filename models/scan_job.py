"""
Thực thể ORM quản lý mục tiêu quét (ScanTarget), phiên quét (ScanSession / ScanJob)
và danh sách các điểm cuối thu thập được từ Crawler (CrawledEndpoint).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.crypto_utils import EncryptedText
from models.base import Base, TimestampMixin, utc_now

if TYPE_CHECKING:
    from models.vulnerability import VulnerabilityFinding


class ScanStatus(str, Enum):
    """Trạng thái vòng đời của một phiên quét."""

    PENDING = "PENDING"
    CRAWLING = "CRAWLING"
    SCANNING = "SCANNING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanTarget(Base, TimestampMixin):
    """Bảng quản lý thông tin mục tiêu kiểm thử (Target Website)."""

    __tablename__ = "scan_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    sessions: Mapped[list["ScanSession"]] = relationship(
        "ScanSession",
        back_populates="target",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanSession(Base, TimestampMixin):
    """
    Bảng quản lý một phiên quét (ScanSession / ScanJob).
    Lưu trữ cấu hình quét, trạng thái tiến độ và thống kê tổng hợp.
    """

    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default=ScanStatus.PENDING.value,
        nullable=False,
        index=True,
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    modules_enabled: Mapped[list[str]] = mapped_column(
        JSON,
        default=lambda: ["sqli", "xss", "csrf", "headers"],
        nullable=False,
    )
    start_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=True,
    )
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary_stats: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=lambda: {
            "total_endpoints": 0,
            "total_findings": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
        },
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Quan hệ 1-N với ScanTarget, CrawledEndpoint và VulnerabilityFinding
    target: Mapped["ScanTarget"] = relationship("ScanTarget", back_populates="sessions")
    endpoints: Mapped[list["CrawledEndpoint"]] = relationship(
        "CrawledEndpoint",
        back_populates="session",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["VulnerabilityFinding"]] = relationship(
        "VulnerabilityFinding",
        back_populates="session",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "target_url": self.target.url if self.target else None,
            "user_id": self.user_id,
            "status": self.status,
            "progress": self.progress,
            "max_depth": self.max_depth,
            "modules_enabled": self.modules_enabled,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "summary_stats": self.summary_stats,
            "error_message": self.error_message,
        }


class CrawledEndpoint(Base, TimestampMixin):
    """
    Bảng lưu trữ các URL/Endpoint và cấu trúc Form/Tham số thu thập được từ Crawler.
    URL nội bộ được mã hóa At-Rest bằng AES-256 thông qua EncryptedText.
    """

    __tablename__ = "crawled_endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Bảo vệ URL nội bộ ở trạng thái At-Rest bằng AES-256
    url: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    method: Mapped[str] = mapped_column(String(16), default="GET", nullable=False)
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    params_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    session: Mapped["ScanSession"] = relationship("ScanSession", back_populates="endpoints")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "url": self.url,
            "method": self.method,
            "depth": self.depth,
            "params_schema": self.params_schema,
        }


# Alias tương thích với tên file scan_job.py
ScanJob = ScanSession
