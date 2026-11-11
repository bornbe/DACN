"""
Module cấu hình trung tâm cho hệ thống OWASP Web Scanner.
Đọc các biến môi trường từ file .env và cung cấp các lớp Config theo môi trường.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

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


def parse_trusted_proxies(raw: Any) -> tuple[str, ...]:
    """
    Chuẩn hóa danh sách IP hoặc dải CIDR của các reverse proxy được tin cậy.
    Hỗ trợ chuỗi phân tách bằng dấu phẩy hoặc iterable các chuỗi.
    """
    if not raw or isinstance(raw, bool):
        return ()
    if isinstance(raw, str):
        candidates = raw.split(",")
    elif isinstance(raw, (list, tuple, set, frozenset)):
        candidates = [str(item) for item in raw]
    else:
        return ()

    cleaned: list[str] = []
    for item in candidates:
        entry = item.strip()
        if not entry:
            continue
        # Bỏ qua các giá trị cấu hình kiểu boolean cũ ("true", "false", "1", "0", "yes", "no")
        if entry.lower() in {"true", "false", "1", "0", "yes", "no"}:
            continue
        ipaddress.ip_network(entry, strict=False)
        if entry not in cleaned:
            cleaned.append(entry)
    return tuple(cleaned)


def validate_production_secrets(secret_key: str | None, jwt_secret_key: str | None) -> None:
    """
    Ở môi trường production, không cho phép dùng secret mặc định, rỗng hoặc quá ngắn.
    Nếu vi phạm, dừng khởi động ứng dụng để tránh bị giả mạo session/JWT.
    """
    defaults = {DEFAULT_SECRET_KEY, DEFAULT_JWT_SECRET_KEY}
    weak: list[str] = []
    for name, value in (
        ("SECRET_KEY", secret_key),
        ("JWT_SECRET_KEY", jwt_secret_key),
    ):
        normalized = value.strip() if isinstance(value, str) else ""
        if not normalized or normalized in defaults or len(normalized) < MIN_SECRET_LENGTH:
            weak.append(name)
    if weak:
        raise RuntimeError(
            "Môi trường production yêu cầu đặt biến môi trường an toàn (>= "
            f"{MIN_SECRET_LENGTH} ký tự, không dùng giá trị mặc định) cho: "
            + ", ".join(weak)
        )


def validate_single_process_config(worker_processes: int | str | None = 1) -> None:
    """
    Kiến trúc hiện tại lưu rate-limit counter, hàng đợi scan (queue.Queue) và
    tín hiệu hủy (threading.Event) trong bộ nhớ của một process duy nhất.
    Từ chối cấu hình nhiều worker process để tránh lệch trạng thái và chạy trùng scan.
    """
    if worker_processes is None:
        return
    try:
        count = int(worker_processes)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Giá trị WORKER_PROCESSES không hợp lệ: {worker_processes!r}") from exc
    if count != 1:
        raise RuntimeError(
            "Ứng dụng chỉ hỗ trợ triển khai single-process (WORKER_PROCESSES=1 / "
            "gunicorn --workers 1 --threads N) do hàng đợi scan, tín hiệu dừng và "
            "rate limiter lưu trong RAM của từng process."
        )


class Config:
    """Cấu hình cơ sở dùng chung cho toàn hệ thống."""

    BASE_DIR: Path = BASE_DIR
    APP_ENV: str = os.getenv("APP_ENV", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", DEFAULT_JWT_SECRET_KEY)

    # Rate limiter: chỉ tin X-Forwarded-For khi remote_addr thuộc danh sách TRUSTED_PROXIES.
    # Mặc định rỗng: không tin tưởng header X-Forwarded-For từ bất kỳ nguồn nào.
    TRUSTED_PROXIES: tuple[str, ...] = parse_trusted_proxies(os.getenv("TRUSTED_PROXIES", ""))
    TRUSTED_PROXY: bool = False

    # Giới hạn triển khai single-process (1 process + background worker thread).
    WORKER_PROCESSES: int = int(os.getenv("WORKER_PROCESSES", os.getenv("WEB_CONCURRENCY", "1")))

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

    APP_ENV: str = "development"
    DEBUG: bool = True


class TestingConfig(Config):
    """Cấu hình môi trường kiểm thử tự động (Unit Testing)."""

    APP_ENV: str = "testing"
    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    ENCRYPTION_MASTER_KEY: str = "dGVzdC1tYXN0ZXIta2V5LTMyLWJ5dGVzLWxvbmc="


class ProductionConfig(Config):
    """Cấu hình môi trường triển khai thực tế (Production)."""

    APP_ENV: str = "production"
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
