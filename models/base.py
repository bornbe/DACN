"""
Khởi tạo lớp cơ sở SQLAlchemy ORM (DeclarativeBase) và quản lý kết nối Database.
Hỗ trợ chạy độc lập cho cả ứng dụng CLI, Background Worker và Web API (Flask).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import DateTime, create_engine
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from config.config import Config


def utc_now() -> datetime:
    """Trả về thời gian UTC hiện tại."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Lớp cơ sở cho tất cả các thực thể ORM trong hệ thống."""
    pass


class TimestampMixin:
    """Mixin tự động bổ sung trường thời gian khởi tạo và cập nhật."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )


_engine: Engine | None = None
_engine_uri: str | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _is_sqlite_memory(uri: str) -> bool:
    url = make_url(uri)
    return url.get_backend_name() == "sqlite" and url.database in (None, "", ":memory:")


def get_engine(database_uri: str | None = None) -> Engine:
    """Tạo hoặc lấy SQLAlchemy Engine."""
    global _engine, _engine_uri
    uri = database_uri or Config.SQLALCHEMY_DATABASE_URI
    # So sánh theo chuỗi URI gốc: str(engine.url) che mật khẩu thành '***' nên luôn khác URI có mật khẩu
    if _engine is None or _engine_uri != uri:
        kwargs: dict = {}
        if uri.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if _is_sqlite_memory(uri):
                # DB in-memory: dùng chung một kết nối cho mọi luồng (Background Worker) để thấy cùng dữ liệu
                kwargs["poolclass"] = StaticPool
        _engine = create_engine(uri, future=True, **kwargs)
        _engine_uri = uri
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Lấy sessionmaker gắn với Engine hiện hành."""
    global _SessionLocal
    target_engine = engine or get_engine()
    if _SessionLocal is None or _SessionLocal.kw.get("bind") is not target_engine:
        _SessionLocal = sessionmaker(
            bind=target_engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _SessionLocal


def get_db_session() -> Generator[Session, None, None]:
    """Generator cung cấp phiên làm việc CSDL và đảm bảo đóng kết nối an toàn."""
    session_factory = get_session_factory()
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def init_db(database_uri: str | None = None) -> Engine:
    """Khởi tạo toàn bộ bảng CSDL từ ORM Metadata."""
    # Import đầy đủ các models để đăng ký vào Base.metadata
    import models.scan_job  # noqa: F401
    import models.user  # noqa: F401
    import models.vulnerability  # noqa: F401

    engine = get_engine(database_uri)
    Base.metadata.create_all(bind=engine)
    return engine
