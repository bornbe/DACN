"""
Module mã hóa bảo vệ dữ liệu nhạy cảm At-Rest (Issue #1.2).
Sử dụng thuật toán AES-256-GCM thông qua thư viện cryptography và tích hợp
SQLAlchemy TypeDecorator để tự động mã hóa/giải mã các trường dữ liệu nhạy cảm
(như payload, target_url nội bộ, bằng chứng phản hồi HTTP) khi lưu trữ trong CSDL.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import Text, TypeDecorator

from config.config import Config


class EncryptionService:
    """
    Dịch vụ mã hóa và giải mã dữ liệu theo chuẩn AES-256-GCM.
    - Độ dài khóa: 256-bit (32 bytes).
    - Độ dài Nonce (IV): 96-bit (12 bytes) sinh ngẫu nhiên an toàn cho mỗi lần mã hóa.
    - Định dạng lưu trữ: Chuỗi Base64 của (nonce [12 bytes] + ciphertext + auth_tag [16 bytes]).
    """

    NONCE_SIZE = 12
    KEY_SIZE = 32

    def __init__(self, master_key: str | bytes | None = None) -> None:
        raw_key = master_key or os.getenv("ENCRYPTION_MASTER_KEY") or Config.ENCRYPTION_MASTER_KEY
        self._key: bytes = self._normalize_key(raw_key)
        self._aesgcm = AESGCM(self._key)

    @classmethod
    def _normalize_key(cls, raw_key: str | bytes) -> bytes:
        """
        Chuẩn hóa khóa đầu vào thành đúng 32 bytes (256 bits) cho AES-256:
        1. Nếu là bytes 32-byte -> giữ nguyên.
        2. Nếu là chuỗi Base64 giải mã ra 32-byte -> dùng trực tiếp.
        3. Nếu là chuỗi Hex 64 ký tự -> chuyển sang 32-byte.
        4. Trường hợp khác -> băm SHA-256 để thu được khóa 32-byte chuẩn.
        """
        if isinstance(raw_key, bytes):
            if len(raw_key) == cls.KEY_SIZE:
                return raw_key
            return hashlib.sha256(raw_key).digest()

        key_str = raw_key.strip()
        if not key_str:
            raise ValueError("ENCRYPTION_MASTER_KEY không được để trống.")

        # Thử giải mã Hex 64 ký tự
        if len(key_str) == 64:
            try:
                return bytes.fromhex(key_str)
            except ValueError:
                pass

        # Thử giải mã Base64
        try:
            decoded = base64.b64decode(key_str, validate=True)
            if len(decoded) == cls.KEY_SIZE:
                return decoded
        except Exception:
            pass

        # Fallback: Dẫn xuất 32 bytes bằng SHA-256
        return hashlib.sha256(key_str.encode("utf-8")).digest()

    @staticmethod
    def generate_master_key() -> str:
        """Sinh khóa ngẫu nhiên 32 bytes (256-bit) mã hóa dưới dạng Base64."""
        return base64.b64encode(os.urandom(EncryptionService.KEY_SIZE)).decode("ascii")

    def encrypt(self, plaintext: str | None) -> str | None:
        """
        Mã hóa chuỗi văn bản thuần (plaintext) bằng AES-256-GCM.
        Trả về chuỗi Base64 chứa Nonce + Ciphertext + Tag.
        """
        if plaintext is None:
            return None
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)

        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode("ascii")

    def decrypt(self, token: str | None) -> str | None:
        """
        Giải mã chuỗi Base64 đã mã hóa bằng AES-256-GCM về văn bản thuần.
        Ném ValueError nếu dữ liệu bị thay đổi trái phép hoặc sai khóa.
        """
        if token is None:
            return None
        try:
            raw_data = base64.b64decode(token.encode("ascii"))
            if len(raw_data) < self.NONCE_SIZE + 16:
                raise ValueError("Dữ liệu mã hóa không hợp lệ hoặc bị cắt ngắn.")
            nonce = raw_data[: self.NONCE_SIZE]
            ciphertext = raw_data[self.NONCE_SIZE :]
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Giải mã AES-256 thất bại: {exc}") from exc


# Singleton mặc định dùng cho SQLAlchemy TypeDecorator
_default_encryption_service: EncryptionService | None = None


def get_encryption_service() -> EncryptionService:
    """Lấy instance EncryptionService hiện hành."""
    global _default_encryption_service
    if _default_encryption_service is None:
        _default_encryption_service = EncryptionService()
    return _default_encryption_service


class EncryptedText(TypeDecorator):
    """
    Kiểu dữ liệu tùy chỉnh cho SQLAlchemy ORM (Custom TypeDecorator).
    Tự động mã hóa AES-256-GCM trước khi ghi xuống CSDL (INSERT/UPDATE)
    và tự động giải mã khi truy vấn từ CSDL (SELECT).
    """

    impl = Text
    cache_ok = True

    def __init__(self, master_key: str | bytes | None = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._custom_key = master_key

    def _service(self) -> EncryptionService:
        if self._custom_key is not None:
            return EncryptionService(self._custom_key)
        return get_encryption_service()

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        """Được SQLAlchemy gọi tự động trước khi lưu vào Database."""
        if value is None:
            return None
        return self._service().encrypt(value)

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        """Được SQLAlchemy gọi tự động khi đọc dữ liệu từ Database."""
        if value is None:
            return None
        return self._service().decrypt(value)
