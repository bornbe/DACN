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

# Giá trị secret mặc định (CHỈ dùng cho development) và độ dài tối thiểu bắt buộc ở production.
DEFAULT_SECRET_KEY = "dev-secret-key-change-in-production"
DEFAULT_JWT_SECRET_KEY = "dev-jwt-secret-key-change-in-production"
MIN_SECRET_LENGTH = 32


def validate_production_secrets(secret_key: str, jwt_secret_key: str) -> None:
    """
    Fix review (Critical): ở môi trường production, không cho phép dùng secret mặc định
    hoặc secret quá ngắn. Nếu vi phạm, DỪNG khởi động ứng dụng để tránh bị giả mạo JWT.
    """
    weak: list[str] = []
    for name, value, default in (
        ("SECRET_KEY", secret_key, DEFAULT_SECRET_KEY),
        ("JWT_SECRET_KEY", jwt_secret_key, DEFAULT_JWT_SECRET_KEY),
    ):
        if not value or value == default or len(value) < MIN_SECRET_LENGTH:
            weak.append(name)
    if weak:
        raise RuntimeError(
            "Môi trường production yêu cầu đặt biến môi trường an toàn (>= "
            f"{MIN_SECRET_LENGTH} ký tự, không dùng giá trị mặc định) cho: "
            + ", ".join(weak)
        )


class Config:
    """Cấu hình cơ sở dùng chung cho toàn hệ thống."""

    BASE_DIR: Path = BASE_DIR
    APP_ENV: str = os.getenv("APP_ENV", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", DEFAULT_JWT_SECRET_KEY)
    # Rate limiter: tin tưởng header proxy (X-Forwarded-For) hay không (mặc định: không).
    TRUSTED_PROXY: bool = os.getenv("TRUSTED_PROXY", "false").lower() in ("1", "true", "yes")

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