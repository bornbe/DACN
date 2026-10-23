"""
Script khởi tạo và quản lý lược đồ Cơ sở dữ liệu (Database Initialization & Migration).
Có thể chạy trực tiếp bằng lệnh:
    python -m migrations.env
"""

from __future__ import annotations

from sqlalchemy import inspect

from config.config import Config
from models.base import init_db


def run_migrations(database_uri: str | None = None) -> list[str]:
    """
    Khởi tạo tất cả các bảng trong cơ sở dữ liệu theo định nghĩa SQLAlchemy ORM
    và trả về danh sách các bảng đã tạo.
    """
    engine = init_db(database_uri)
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    return tables


if __name__ == "__main__":
    created_tables = run_migrations()
    print(f"[+] Đã khởi tạo CSDL thành công tại: {Config.SQLALCHEMY_DATABASE_URI}")
    print(f"[+] Danh sách bảng hiện có ({len(created_tables)}): {', '.join(created_tables)}")
