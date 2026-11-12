"""
Kiểm thử cô lập phạm vi (Scope Isolation) và đồng bộ chính sách mục tiêu giữa API, CLI và Engine - Yêu cầu #1 & PR #11 Mục 3, 4.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.engine.scan_context import ScanContext
from core.engine.scan_engine import ScanEngine
from core.scanners import ALL_MODULES
from core.security.scope_policy import MAX_SCAN_DEPTH, MAX_SCAN_PAGES, build_authorized_scope
from core.security.target_validator import TargetValidationError, validate_target_url
from scanner import main as cli_main
from schemas.requested_scope_schema import validate_scan_request


def test_scope_isolation_overrides_malicious_client_parameters():
    """
    Khi client cố tình truyền các trường mở rộng phạm vi trái phép (`allowed_domains`,
    `allow_private_ip`, `follow_external_redirects`, `verify_tls=False`, `max_depth=999`),
    `build_authorized_scope` phải ghi đè và khóa chặt vào mục tiêu loopback đã xác thực.
    """
    malicious_payload = {
        "url": "http://localhost:8080/app/",
        "max_depth": 999,
        "max_pages": 999999,
        "timeout": 9999,
        "modules": ["sqli", "headers"],
        "allowed_domains": ["evil.example.com", "169.254.169.254", "*.internal"],
        "allow_private_ip": True,
        "follow_external_redirects": True,
        "verify_tls": False,
    }

    authorized = build_authorized_scope(malicious_payload)
    assert authorized["allowed_domains"] == ["localhost"]
    assert authorized["max_depth"] == MAX_SCAN_DEPTH
    assert authorized["max_pages"] == MAX_SCAN_PAGES
    assert authorized["loopback_only"] is True
    assert authorized["verify_tls"] is True
    assert authorized["follow_external_redirects"] is False
    assert authorized["modules"] == ["sqli", "headers"]


def test_target_validator_rejects_credentials_and_does_not_leak_secrets_in_error():
    """URL chứa username:password bị từ chối và thông báo lỗi tuyệt đối không làm lộ mật khẩu."""
    secret_pw = "SuperSecretToken_987654321"
    url_with_creds = f"http://admin:{secret_pw}@127.0.0.1:8080/private"

    with pytest.raises(TargetValidationError) as exc_info:
        validate_target_url(url_with_creds)

    assert secret_pw not in str(exc_info.value)
    assert "admin" not in str(exc_info.value)


def test_api_cli_and_engine_enforce_identical_loopback_policy():
    """
    Xác minh API (`validate_scan_request`), CLI (`scanner.py`) và `ScanEngine` cùng chấp nhận
    mục tiêu loopback hợp lệ và cùng từ chối host ngoài loopback mà không gửi bất kỳ HTTP request nào.
    """
    allowed_urls = (
        "http://127.0.0.1:8080",
        "http://127.0.0.2:3000/test",
        "http://[::1]:8000/",
        "http://localhost:5000",
        "http://sub.localhost:4280",
    )
    for url in allowed_urls:
        validated = validate_scan_request({"url": url, "max_depth": 1, "modules": ["headers"]})
        assert validated["url"] == url

    rejected_urls = (
        "http://example.com",
        "https://google.com",
        "http://192.168.1.10:8080",
        "http://10.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "ftp://127.0.0.1:21/file",
        "http://user:pass@127.0.0.1:8080/",
        "http://localhost.evil.com/",
    )
    for bad_url in rejected_urls:
        # 1. API schema từ chối
        with pytest.raises(ValueError):
            validate_scan_request({"url": bad_url})

        # 2. CLI từ chối qua parser.error (SystemExit(2)) trước khi gọi ScanEngine
        with patch("scanner.ScanEngine") as mock_engine:
            with pytest.raises(SystemExit) as exit_info:
                cli_main(["-u", bad_url, "-m", "headers", "--no-db", "--quiet"])
            assert exit_info.value.code == 2
            mock_engine.assert_not_called()

        # 3. ScanEngine từ chối và chuyển trạng thái FAILED mà không gọi BFSCrawler
        with patch("core.engine.scan_engine.BFSCrawler") as mock_crawler:
            report = ScanEngine(ScanContext(target_url=bad_url, modules=list(ALL_MODULES))).run()
            assert report.status == "FAILED"
            mock_crawler.assert_not_called()
