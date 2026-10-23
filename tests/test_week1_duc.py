"""
Bộ kiểm thử đơn vị (Unit Tests) cho các nhiệm vụ Tuần 1 của Nguyễn Tiến Đức:
- Issue #1.1: Kiến trúc Clean Architecture & Các thực thể SQLAlchemy ORM.
- Issue #1.2: Mã hóa bảo vệ dữ liệu nhạy cảm At-Rest bằng AES-256-GCM.
- Issue #1.3: Bộ nạp cấu hình mẫu thử nghiệm và danh mục tiêu chuẩn OWASP.
"""

from __future__ import annotations

import unittest
from sqlalchemy import text

from config.crypto_utils import EncryptionService
from core.utils.payload_loader import PayloadLoader
from models import (
    Base,
    CrawledEndpoint,
    ScanSession,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
    User,
    VulnerabilityFinding,
    get_engine,
    get_session_factory,
    init_db,
)


class TestWeek1DucTasks(unittest.TestCase):
    """Kiểm thử toàn diện Module 1 (Tuần 1 - Nguyễn Tiến Đức)."""

    def setUp(self) -> None:
        """Khởi tạo CSDL SQLite in-memory phục vụ mỗi test case độc lập."""
        self.db_uri = "sqlite:///:memory:"
        self.engine = init_db(self.db_uri)
        self.SessionLocal = get_session_factory(self.engine)
        self.session = self.SessionLocal()

    def tearDown(self) -> None:
        self.session.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_aes256_encryption_service_roundtrip_and_tamper_detection(self) -> None:
        """Kiểm tra mã hóa/giải mã AES-256-GCM và khả năng phát hiện can thiệp dữ liệu."""
        key = EncryptionService.generate_master_key()
        service = EncryptionService(master_key=key)

        secret_text = "http://internal.corp.local/admin?debug=true"
        cipher_1 = service.encrypt(secret_text)
        cipher_2 = service.encrypt(secret_text)

        self.assertIsNotNone(cipher_1)
        self.assertNotEqual(cipher_1, secret_text)
        # Mỗi lần mã hóa sinh Nonce ngẫu nhiên nên 2 bản mã phải khác nhau
        self.assertNotEqual(cipher_1, cipher_2)

        # Giải mã chính xác về văn bản gốc
        self.assertEqual(service.decrypt(cipher_1), secret_text)
        self.assertEqual(service.decrypt(cipher_2), secret_text)

        # Kiểm tra chống giả mạo dữ liệu (Authenticated Encryption)
        tampered = cipher_1[:-4] + "AAAA"
        with self.assertRaises(ValueError):
            service.decrypt(tampered)

    def test_orm_models_and_at_rest_encryption_in_database(self) -> None:
        """
        Kiểm tra các thực thể ORM (ScanTarget, ScanSession, CrawledEndpoint, VulnerabilityFinding)
        và xác minh dữ liệu nhạy cảm thực sự được lưu ở dạng mã hóa AES-256 dưới bảng SQL.
        """
        # 1. Tạo User
        user = User(username="tienduc", email="tienduc.81.03@gmail.com")
        user.set_password("StrongPass!2026")
        self.session.add(user)
        self.session.commit()
        self.assertTrue(user.check_password("StrongPass!2026"))
        self.assertFalse(user.check_password("WrongPassword"))

        # 2. Tạo ScanTarget & ScanSession
        target = ScanTarget(
            name="DVWA Local Testbed",
            url="http://127.0.0.1:8080",
            description="Môi trường thử nghiệm nội bộ",
        )
        self.session.add(target)
        self.session.flush()

        scan_session = ScanSession(
            target_id=target.id,
            user_id=user.id,
            status=ScanStatus.RUNNING.value,
            max_depth=3,
            modules_enabled=["sqli", "xss", "csrf", "headers"],
        )
        self.session.add(scan_session)
        self.session.flush()

        # 3. Tạo CrawledEndpoint và VulnerabilityFinding chứa thông tin nhạy cảm
        sensitive_url = "http://127.0.0.1:8080/vulnerabilities/sqli/?id=1"
        sensitive_probe = "SCANNER_SQLI_ERROR_CANARY_01"
        sensitive_evidence = "HTTP/1.1 500 Internal Server Error - SQL syntax near..."

        endpoint = CrawledEndpoint(
            session_id=scan_session.id,
            url=sensitive_url,
            method="GET",
            depth=1,
            params_schema={"id": "text", "Submit": "submit"},
        )
        finding = VulnerabilityFinding(
            session_id=scan_session.id,
            vuln_type="SQL Injection (Error-based)",
            severity=SeverityLevel.HIGH.value,
            target_url=sensitive_url,
            param="id",
            payload=sensitive_probe,
            evidence=sensitive_evidence,
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            remediation="Sử dụng Prepared Statements.",
        )
        self.session.add_all([endpoint, finding])
        self.session.commit()

        # 4. Truy vấn thô (Raw SQL) trực tiếp xuống bảng để chứng minh dữ liệu KHÔNG lưu clear-text
        raw_row = self.session.execute(
            text("SELECT target_url, payload, evidence FROM vulnerability_findings WHERE id = :id"),
            {"id": finding.id},
        ).fetchone()

        self.assertIsNotNone(raw_row)
        raw_target_url, raw_payload, raw_evidence = raw_row
        self.assertNotEqual(raw_target_url, sensitive_url)
        self.assertNotEqual(raw_payload, sensitive_probe)
        self.assertNotEqual(raw_evidence, sensitive_evidence)

        # 5. Truy vấn qua SQLAlchemy ORM để xác minh dữ liệu được giải mã tự động
        loaded_finding = self.session.get(VulnerabilityFinding, finding.id)
        self.assertIsNotNone(loaded_finding)
        self.assertEqual(loaded_finding.target_url, sensitive_url)
        self.assertEqual(loaded_finding.payload, sensitive_probe)
        self.assertEqual(loaded_finding.evidence, sensitive_evidence)
        self.assertEqual(len(loaded_finding.fingerprint), 64)

    def test_payload_loader_and_owasp_catalog(self) -> None:
        """Kiểm tra bộ nạp cấu hình mẫu kiểm thử và danh mục chuẩn OWASP (Issue #1.3)."""
        loader = PayloadLoader()

        headers_specs = loader.load_security_headers_spec()
        self.assertGreaterEqual(len(headers_specs), 4)
        header_names = {item["header"] for item in headers_specs}
        self.assertIn("Strict-Transport-Security", header_names)
        self.assertIn("Content-Security-Policy", header_names)
        self.assertIn("X-Frame-Options", header_names)
        self.assertIn("X-Content-Type-Options", header_names)

        catalog = loader.load_owasp_catalog()
        self.assertIn("categories", catalog)
        self.assertIn("sqli", catalog["categories"])
        self.assertIn("xss", catalog["categories"])
        self.assertIn("csrf", catalog["categories"])
        self.assertIn("security_headers", catalog["categories"])


if __name__ == "__main__":
    unittest.main()
