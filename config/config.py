"""
Module cấu hình trung tâm cho hệ thống OWASP Web Scanner.
Đọc các biến môi trường từ file .env và cung cấp các lớp Config theo môi trường.
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    BASE_DIR = Path(__file__).resolve().parent.parent
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Cấu hình cơ sở dùng chung cho toàn hệ thống."""

    BASE_DIR: Path = BASE_DIR
    APP_ENV: str = os.getenv("APP_ENV", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-change-in-production")

    # Cấu hình Database SQLAlchemy
    SQLALCHEMY_DATABASE_URI: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'scannerweb.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Khóa chủ phục vụ mã hóa dữ liệu nhạy cảm At-Rest (AES-256)
    ENCRYPTION_MASTER_KEY: str = os.getenv(
        "ENCRYPTION_MASTER_KEY",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    )

    # Cấu hình giới hạn mặc định cho Crawler & Scanner
    DEFAULT_MAX_DEPTH: int = int(os.getenv("DEFAULT_MAX_DEPTH", "2"))
    DEFAULT_MAX_PAGES: int = int(os.getenv("DEFAULT_MAX_PAGES", "100"))
    DEFAULT_REQUEST_TIMEOUT: int = int(os.getenv("DEFAULT_REQUEST_TIMEOUT", "10"))

    # Đường dẫn thư mục tài nguyên mẫu kiểm thử và báo cáo
    PAYLOADS_DIR: Path = BASE_DIR / "payloads"
    REPORTS_DIR: Path = BASE_DIR / "reports"


class DevelopmentConfig(Config):
    """Cấu hình môi trường phát triển (Development)."""
    DEBUG: bool = True


class TestingConfig(Config):
    """Cấu hình môi trường kiểm thử tự động (Unit Testing)."""
    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    ENCRYPTION_MASTER_KEY: str = "dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWxvbmc="


class ProductionConfig(Config):
    """Cấu hình môi trường triển khai thực tế (Production)."""
    DEBUG: bool = False


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(env_name: str | None = None) -> type[Config]:
    """Trả về lớp cấu hình tương ứng với tên môi trường."""
    env = (env_name or os.getenv("APP_ENV", "development")).lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
