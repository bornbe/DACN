"""
Kiểm thử tích hợp và đơn vị cho:
- Module 6.1: Giao diện Web Dashboard, trang chi tiết Scan, bộ lọc client-side, đồng bộ danh sách module, bảo mật DOM/XSS và lưu trữ JWT.
- Module 6.2: API tải báo cáo kỹ thuật TXT/PDF (`GET /api/scans/<id>/report?format=pdf|txt`), phân quyền chủ sở hữu, nhúng font Unicode / fallback ASCII transliteration, escape ký tự HTML/XML đặc biệt và đồng bộ thống kê severity.
- Module 7.1 & 7.2: Công cụ tính toán chỉ số thực nghiệm (TP, FP, FN, Precision, Recall, F1-Score, thời gian quét trung bình), chuẩn hóa chính xác CWE (`CWE-<number>`), deduplication, mẫu số bằng 0, parser OWASP ZAP artifact và CLI với `benchmark/fixtures/`.
- Kiểm tra chính sách mục tiêu Loopback-Only thống nhất trên API, CLI và ScanEngine (PR #11).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import scanner as scanner_cli
from app import create_app
from benchmark.evaluate import (
    MatchingConfig,
    build_parser as build_benchmark_parser,
    compare_tools,
    compute_classification_metrics,
    compute_timing_metrics,
    extract_cwe_codes,
    extract_matching_key,
    main as benchmark_cli_main,
    normalize_cwe_id,
    normalize_endpoint_path,
    normalize_vuln_category,
    parse_tool_artifact,
    render_benchmark_markdown,
)
from core.engine.scan_engine import ScanContext, ScanEngine
from core.scanners import ALL_MODULES, UNSUPPORTED_MODULES, load_scanner_class
from core.scanners.ssrf_scanner import SSRFScanner, SSRFScannerUnsupportedError
from models.base import Base
from models.scan_job import CrawledEndpoint, ScanStatus
from models.user import User
from models.vulnerability import VulnerabilityFinding
from services import report_service, scan_service


@pytest.fixture()
def client():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "module-six-seven-test-secret-key-32-bytes-min",
            "RATE_LIMIT_MAX_REQUESTS": 200,
        }
    )
    engine = app.extensions["database_engine"]
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with app.test_client() as test_client:
        yield test_client
    Base.metadata.drop_all(bind=engine)


def _register_and_login(
    client,
    username: str = "owner-user",
    email: str = "owner@example.test",
    password: str = "secure-pass-123",
) -> tuple[int, dict[str, str]]:
    reg = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert reg.status_code == 201
    user_id = reg.get_json()["user"]["id"]
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    token = login.get_json()["access_token"]
    return user_id, {"Authorization": f"Bearer {token}"}


def _seed_completed_scan_with_special_chars(client, user_id: int, stale_summary: bool = False) -> int:
    factory = client.application.extensions["database_session_factory"]
    start = datetime(2026, 11, 12, 6, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(seconds=12.5)
    with factory() as db:
        scan = scan_service.create_scan(
            db,
            user_id=user_id,
            url="http://127.0.0.1:8080",
            max_depth=2,
            modules=["sqli", "xss", "headers"],
        )
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.start_time = start
        scan.end_time = end
        if stale_summary:
            # Cố tình ghi summary_stats sai lệch để kiểm tra report_service tự tính lại từ findings thực tế:
            scan.summary_stats = {
                "pages_crawled": 3,
                "total_endpoints": 2,
                "total_findings": 0,
                "severity_counts": {
                    "CRITICAL": 99,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                },
            }
        else:
            scan.summary_stats = {
                "pages_crawled": 3,
                "total_endpoints": 2,
                "total_findings": 2,
                "severity_counts": {
                    "CRITICAL": 0,
                    "HIGH": 1,
                    "MEDIUM": 0,
                    "LOW": 1,
                    "INFO": 0,
                },
            }
        db.add(
            CrawledEndpoint(
                session_id=scan.id,
                url="http://127.0.0.1:8080/search",
                method="GET",
                depth=1,
                params_schema={"q": "test"},
            )
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan.id,
                vuln_type="SQL Injection (Error-based) <tag>&\"'\x00\x07",
                severity="HIGH",
                target_url="http://127.0.0.1:8080/search?q=1",
                param="q",
                payload="1' OR '1'='1 -- <script>alert(1)</script>&\"'\x1f",
                evidence="MySQL error near '<svg onload=alert(1)>' & \"quote\"",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                remediation="Sử dụng Prepared Statements / Parameterized Queries để bảo vệ tiếng Việt Đắk Lắk.",
            )
        )
        db.add(
            VulnerabilityFinding(
                session_id=scan.id,
                vuln_type="Unencoded Input Reflection (Needs Review)",
                severity="LOW",
                target_url="http://127.0.0.1:8080/search",
                param="q",
                payload="xss123<>\"'",
                evidence="Ngữ cảnh HTML; ký tự chưa mã hóa: <>",
                cwe_id="CWE-79",
                owasp_category="A03:2021-Injection",
                remediation="Mã hóa HTML entity trước khi phản chiếu dữ liệu người dùng.",
            )
        )
        db.commit()
        return scan.id


# ==============================================================================
# MODULE 6.1 — WEB DASHBOARD, MODULE SYNC & CLIENT-SIDE FINDINGS FILTER (ISSUES 4 & 5)
# ==============================================================================


def test_dashboard_and_scan_detail_pages_render_and_static_assets_safe(client):
    """Kiểm tra route giao diện Dashboard, Scan Detail, bộ lọc findings và tài nguyên JS/CSS an toàn."""
    for path in ("/", "/dashboard"):
        resp = client.get(path)
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "newScanForm" in html
        assert "severityChart" in html
        assert "scansTable" in html
        assert "/static/js/app.js" in html
        assert "/static/js/chart.js" in html

        # Issue 4: Kiểm tra các checkbox module trên UI khớp chính xác với ALL_MODULES:
        checkbox_values = set(
            re.findall(r'<input[^>]*class="[^"]*scan-module-checkbox[^"]*"[^>]*value="([^"]+)"', html)
        )
        assert checkbox_values == set(ALL_MODULES) == {"sqli", "xss", "csrf", "headers"}
        for unsupported in ("auth", "misconfig", "access_control", "ssrf"):
            assert f'value="{unsupported}"' not in html

    detail_resp = client.get("/scans/42")
    assert detail_resp.status_code == 200
    detail_html = detail_resp.get_data(as_text=True)
    assert 'data-session-id="42"' in detail_html
    assert "findingDetailModal" in detail_html
    assert "stopScanBtn" in detail_html
    assert "downloadTxtBtn" in detail_html
    assert "downloadPdfBtn" in detail_html
    # Issue 5: Kiểm tra các phần tử điều khiển lọc findings trên trang chi tiết:
    assert 'id="findingSeverityFilter"' in detail_html
    assert 'id="findingKeywordFilter"' in detail_html
    assert 'id="clearFindingFilterBtn"' in detail_html
    assert 'id="findingsCountBadge"' in detail_html

    # Kiểm tra file static JS không dùng innerHTML bất cẩn, không log JWT, và có hàm lọc findings:
    app_js = client.get("/static/js/app.js").get_data(as_text=True)
    assert "textContent" in app_js
    assert "innerHTML =" not in app_js
    assert "console.log" not in app_js
    assert "function filterFindings(" in app_js
    assert "function renderFilteredFindingsTable(" in app_js
    assert "Không tìm thấy lỗ hổng nào khớp với bộ lọc hiện tại." in app_js


def test_supported_modules_consistency_across_registry_api_cli_and_docs(client):
    """Issue 4: Đồng bộ danh sách module hỗ trợ giữa SCANNER_REGISTRY, API, CLI và README."""
    assert set(ALL_MODULES) == {"sqli", "xss", "csrf", "headers"}
    assert "ssrf" in UNSUPPORTED_MODULES

    # SSRFScanner bị vô hiệu hóa chủ động và không gửi bất kỳ request nào:
    with pytest.raises(LookupError, match="vô hiệu hóa"):
        load_scanner_class("ssrf")

    ssrf_scanner = SSRFScanner()
    with patch.object(ssrf_scanner, "send") as mock_req:
        with pytest.raises(SSRFScannerUnsupportedError):
            ssrf_scanner.scan({"url": "http://127.0.0.1:8080", "method": "GET", "params": {}})  # type: ignore[arg-type]
        mock_req.assert_not_called()

    # API từ chối các module không hỗ trợ (`auth`, `misconfig`, `access_control`, `ssrf`):
    _, headers = _register_and_login(client, "moduser", "moduser@example.test")
    for invalid_mod in ("auth", "misconfig", "access_control", "ssrf"):
        resp = client.post(
            "/api/scans",
            headers=headers,
            json={"url": "http://127.0.0.1:8080", "modules": [invalid_mod], "max_depth": 1},
        )
        assert resp.status_code == 400
        err_json = resp.get_json()
        assert "headers, csrf, sqli, xss" in err_json.get("message", "")

    # CLI từ chối module không hỗ trợ:
    with pytest.raises(SystemExit) as exc_info:
        scanner_cli.main(["-u", "http://127.0.0.1:8080", "-m", "sqli,misconfig"])
    assert exc_info.value.code == 2


# ==============================================================================
# ISSUE 3 — UNIFIED LOOPBACK TARGET POLICY (API, CLI, ENGINE)
# ==============================================================================


def test_loopback_target_policy_enforced_across_api_cli_and_engine(client):
    """Issue 3: Chính sách chỉ cho phép loopback được thực thi thống nhất ở API, CLI và ScanEngine."""
    _, headers = _register_and_login(client, "scopeuser", "scopeuser@example.test")

    forbidden_urls = [
        "https://example.com",
        "http://8.8.8.8",
        "http://192.168.1.10:8080",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "ftp://127.0.0.1:8080",
        "http://admin:secret@127.0.0.1:8080",
    ]
    for bad_url in forbidden_urls:
        # 1. REST API chặn:
        api_resp = client.post(
            "/api/scans",
            headers=headers,
            json={"url": bad_url, "modules": ["headers"], "max_depth": 1},
        )
        assert api_resp.status_code == 400, f"API phải chặn URL: {bad_url}"
        body_text = api_resp.get_data(as_text=True)
        # Không làm lộ secret trong thông báo lỗi:
        assert "module-six-seven-test-secret-key" not in body_text

        # 2. CLI chặn trước khi chạy engine:
        with patch("scanner.ScanEngine") as mock_engine_cls:
            with pytest.raises(SystemExit) as exc_info:
                scanner_cli.main(["-u", bad_url, "-m", "headers"])
            assert exc_info.value.code == 2, f"CLI phải chặn URL: {bad_url}"
            mock_engine_cls.assert_not_called()

        # 3. ScanEngine.run() chặn ngay cả khi được gọi trực tiếp:
        ctx = ScanContext(target_url=bad_url, modules=["headers"], max_depth=1)
        engine = ScanEngine(context=ctx)
        result_report = engine.run()
        assert result_report.status == "FAILED"
        assert result_report.error_message


# ==============================================================================
# MODULE 6.2 — TECHNICAL REPORT DOWNLOAD API & UNICODE PDF (ISSUE 6)
# ==============================================================================


def test_report_endpoint_requires_auth_and_enforces_ownership(client):
    owner_id, owner_headers = _register_and_login(client, "owner1", "owner1@example.test")
    _, stranger_headers = _register_and_login(client, "stranger1", "stranger1@example.test")
    scan_id = _seed_completed_scan_with_special_chars(client, owner_id)

    # 1. Chưa đăng nhập -> 401
    unauth = client.get(f"/api/scans/{scan_id}/report?format=txt")
    assert unauth.status_code == 401

    # 2. Không phải chủ sở hữu -> 404
    forbidden = client.get(f"/api/scans/{scan_id}/report?format=txt", headers=stranger_headers)
    assert forbidden.status_code == 404

    # 3. Scan không tồn tại -> 404
    missing = client.get("/api/scans/999999/report?format=txt", headers=owner_headers)
    assert missing.status_code == 404


def test_report_endpoint_rejects_invalid_formats(client):
    owner_id, owner_headers = _register_and_login(client, "owner2", "owner2@example.test")
    scan_id = _seed_completed_scan_with_special_chars(client, owner_id)

    for bad_query in ("", "?format=", "?format=json", "?format=html", "?format=../txt", "?format=exe"):
        resp = client.get(f"/api/scans/{scan_id}/report{bad_query}", headers=owner_headers)
        assert resp.status_code == 400


def test_report_endpoint_txt_and_pdf_success_with_unicode_and_xml_special_chars(client):
    """Issue 6: Kiểm tra xuất TXT/PDF với tiếng Việt, ký tự XML đặc biệt, ký tự điều khiển và tính lại thống kê."""
    owner_id, owner_headers = _register_and_login(client, "owner3", "owner3@example.test")
    scan_id = _seed_completed_scan_with_special_chars(client, owner_id, stale_summary=True)

    # Xuất TXT thành công và thống kê được tính lại chính xác từ danh sách findings thực tế (1 HIGH, 1 LOW, 0 CRITICAL):
    txt_resp = client.get(f"/api/scans/{scan_id}/report?format=txt", headers=owner_headers)
    assert txt_resp.status_code == 200
    assert "text/plain" in txt_resp.content_type
    assert f'filename="scan-report-{scan_id}.txt"' in txt_resp.headers.get("Content-Disposition", "")
    txt_body = txt_resp.get_data(as_text=True)
    assert "OWASP AUTOMATED PENTEST REPORT" in txt_body
    assert f"Session ID    : #{scan_id}" in txt_body
    assert "http://127.0.0.1:8080" in txt_body
    assert "max_depth=2" in txt_body
    assert "CWE-89" in txt_body
    assert "Findings      : 2  (CRITICAL=0, HIGH=1, MEDIUM=0, LOW=1, INFO=0)" in txt_body
    assert "Prepared Statements" in txt_body
    assert "Đắk Lắk" in txt_body

    # Xuất PDF thành công (hoặc skip rõ lý do nếu thiếu reportlab):
    pytest.importorskip("reportlab", reason="Thư viện reportlab chưa được cài đặt để kiểm thử xuất PDF.")
    pdf_resp = client.get(f"/api/scans/{scan_id}/report?format=pdf", headers=owner_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.content_type == "application/pdf"
    assert f'filename="scan-report-{scan_id}.pdf"' in pdf_resp.headers.get("Content-Disposition", "")
    pdf_bytes = pdf_resp.get_data()
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500
    # Xác nhận font TrueType Unicode được nhúng (CID CMap beginbfchar) và dữ liệu được ghi vào stream PDF:
    assert b"beginbfchar" in pdf_bytes
    assert b"CWE-89" in pdf_bytes


def test_pdf_unicode_font_fallback_and_custom_font_validation(monkeypatch):
    """Issue 6: Kiểm tra fallback sang ASCII transliteration khi thiếu font .ttf và báo lỗi khi cấu hình font sai."""
    pytest.importorskip("reportlab")
    sample_data = {
        "session_id": 77,
        "target_url": "http://127.0.0.1:8080",
        "status": "COMPLETED",
        "max_depth": 1,
        "modules": ["sqli"],
        "summary": {"total_findings": 1, "severity_counts": {"HIGH": 1}},
        "findings": [
            {
                "vuln_name": "Lỗi tiêm SQL tiếng Việt <script>&\"'",
                "severity": "HIGH",
                "target_url": "http://127.0.0.1:8080/login",
                "parameter": "user",
                "payload": "' OR 1=1 --",
                "evidence": "Bằng chứng tiếng Việt Đắk Lắk",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "remediation": "Khắc phục bằng truy vấn tham số hóa.",
            }
        ],
    }

    # 1. Khi không tìm thấy bất kỳ font TTF nào trên hệ thống -> fallback an toàn sang Helvetica + ASCII transliteration:
    with patch("services.report_service._get_unicode_font_candidates", return_value=[]):
        monkeypatch.delenv("REPORT_UNICODE_FONT_PATH", raising=False)
        fallback_pdf = report_service.render_pdf_bytes(sample_data)
        assert fallback_pdf.startswith(b"%PDF")
        assert b"No Unicode TrueType font found; text transliterated to ASCII" in fallback_pdf
        assert b"Dak Lak" in fallback_pdf

    # 2. Khi truyền đường dẫn font tùy chỉnh không tồn tại -> ném RuntimeError rõ ràng:
    monkeypatch.setenv("REPORT_UNICODE_FONT_PATH", "Z:/non_existent_directory/missing_font.ttf")
    with pytest.raises(RuntimeError, match="REPORT_UNICODE_FONT_PATH"):
        report_service.render_pdf_bytes(sample_data)


# ==============================================================================
# MODULE 7.1 & 7.2 — BENCHMARK EVALUATION, CWE NORMALIZATION, FIXTURES & CLI
# ==============================================================================


def test_cwe_exact_normalization_prevents_substring_false_matches():
    """Issue 2: CWE phải được chuẩn hóa thành CWE-<number> và so khớp chính xác, không dính lỗi substring."""
    assert normalize_cwe_id(89) == "CWE-89"
    assert normalize_cwe_id("89") == "CWE-89"
    assert normalize_cwe_id("089") == "CWE-89"
    assert normalize_cwe_id("cwe-089") == "CWE-89"
    assert normalize_cwe_id("CWE-189") == "CWE-189"
    assert normalize_cwe_id("-1") is None
    assert normalize_cwe_id("0") is None
    assert normalize_cwe_id(None) is None

    assert extract_cwe_codes("CWE-189, CWE-89") == ["CWE-189", "CWE-89"]

    # CWE được hỗ trợ ánh xạ đúng:
    assert normalize_vuln_category("", "CWE-89") == "sqli"
    assert normalize_vuln_category("", "89") == "sqli"
    assert normalize_vuln_category("", "CWE-79") == "xss"
    assert normalize_vuln_category("", "CWE-352") == "csrf"
    assert normalize_vuln_category("", "CWE-16") == "headers"
    assert normalize_vuln_category("", "CWE-693") == "headers"
    assert normalize_vuln_category("", "CWE-1021") == "headers"

    # CWE chứa chuỗi con '89', '79', '352', '16' nhưng là mã CWE khác -> tuyệt đối KHÔNG ánh xạ nhầm:
    assert normalize_vuln_category("", "CWE-189") == "cwe-189"
    assert normalize_vuln_category("", "CWE-289") == "cwe-289"
    assert normalize_vuln_category("", "CWE-890") == "cwe-890"
    assert normalize_vuln_category("", "CWE-790") == "cwe-790"
    assert normalize_vuln_category("", "CWE-179") == "cwe-179"
    assert normalize_vuln_category("", "CWE-3520") == "cwe-3520"
    assert normalize_vuln_category("", "CWE-160") == "cwe-160"
    assert normalize_vuln_category("Numeric Error", "CWE-189") == "numeric error"

    # Kiểm tra đối sánh thực tế: Ground truth là SQLi (CWE-89) không được khớp với finding CWE-189 cùng endpoint/param:
    gt = [{"vuln_category": "sqli", "cwe_id": "CWE-89", "target_url": "http://127.0.0.1:4280/vuln", "parameter": "id"}]
    finding_cwe_189 = [
        {"vuln_name": "Numeric Error", "cwe_id": "CWE-189", "target_url": "http://127.0.0.1:4280/vuln", "parameter": "id"}
    ]
    res = compute_classification_metrics(gt, finding_cwe_189)
    assert res["counts"]["tp"] == 0
    assert res["counts"]["fp"] == 1
    assert res["counts"]["fn"] == 1


def test_benchmark_matching_deduplication_and_metrics_calculation():
    ground_truth = [
        {"vuln_category": "sqli", "target_url": "http://127.0.0.1:3000/rest/products/search", "parameter": "q"},
        {"vuln_category": "xss", "target_url": "http://127.0.0.1:3000/search", "parameter": "q"},
        {"vuln_category": "csrf", "target_url": "http://127.0.0.1:3000/profile", "parameter": "username"},
        {"vuln_category": "headers", "target_url": "http://127.0.0.1:3000/", "parameter": ""},
    ]

    # Scanner trả về: 3 TP (trong đó 1 bản ghi SQLi bị lặp 2 lần và 2 bản ghi headers cùng trang),
    # 1 FP (xss ở /contact), và bỏ sót 1 FN (csrf ở /profile).
    findings = [
        {
            "vuln_name": "SQL Injection (Error-based)",
            "cwe_id": "CWE-89",
            "target_url": "http://localhost:3000/rest/products/search?q=apple",
            "parameter": "q",
        },
        {
            "vuln_name": "SQL Injection (Boolean-based)",
            "cwe_id": "CWE-89",
            "target_url": "http://127.0.0.1:3000/rest/products/search/",
            "parameter": "Q",
        },
        {
            "vuln_name": "Unencoded Input Reflection (Needs Review)",
            "cwe_id": "CWE-79",
            "target_url": "http://127.0.0.1:3000/search",
            "parameter": "q",
        },
        {
            "vuln_name": "Missing Security Header: X-Frame-Options",
            "cwe_id": "CWE-1021",
            "target_url": "http://127.0.0.1:3000/",
            "parameter": None,
        },
        {
            "vuln_name": "Weak Security Header: Content-Security-Policy",
            "cwe_id": "CWE-693",
            "target_url": "http://127.0.0.1:3000/",
            "parameter": None,
        },
        {
            "vuln_name": "Cross-Site Scripting",
            "cwe_id": "CWE-79",
            "target_url": "http://127.0.0.1:3000/contact",
            "parameter": "comment",
        },
    ]

    result = compute_classification_metrics(ground_truth, findings)
    counts = result["counts"]
    metrics = result["metrics"]

    assert counts["tp"] == 3
    assert counts["fp"] == 1
    assert counts["fn"] == 1
    assert counts["duplicates_removed"] == 2
    assert counts["unique_findings_total"] == 4

    # Precision = 3 / (3 + 1) = 0.75; Recall = 3 / (3 + 1) = 0.75; F1 = 0.75
    assert metrics["precision"] == pytest.approx(0.75)
    assert metrics["recall"] == pytest.approx(0.75)
    assert metrics["f1_score"] == pytest.approx(0.75)


def test_benchmark_zero_denominators_and_invalid_entries():
    # 1. Cả ground truth và findings đều rỗng -> mẫu số = 0, trả 0.0 an toàn:
    empty_res = compute_classification_metrics([], [])
    assert empty_res["counts"]["tp"] == 0
    assert empty_res["counts"]["fp"] == 0
    assert empty_res["counts"]["fn"] == 0
    assert empty_res["metrics"] == {"precision": 0.0, "recall": 0.0, "f1_score": 0.0}

    # 2. Có Ground Truth nhưng không phát hiện được gì (TP = 0, FP = 0, FN = 1):
    no_findings_res = compute_classification_metrics(
        [{"vuln_category": "sqli", "target_url": "http://127.0.0.1:4280/vuln", "parameter": "id"}],
        [],
    )
    assert no_findings_res["counts"]["fn"] == 1
    assert no_findings_res["metrics"] == {"precision": 0.0, "recall": 0.0, "f1_score": 0.0}

    # 3. Các bản ghi thiếu URL hoặc thiếu loại lỗ hổng bị bỏ qua và đếm vào invalid_*_skipped:
    malformed_res = compute_classification_metrics(
        [{"vuln_category": "", "target_url": ""}, {"not": "valid"}],
        [{"vuln_name": "SQLi", "target_url": ""}, "not-a-dict"],  # type: ignore[list-item]
    )
    assert malformed_res["counts"]["invalid_ground_truth_skipped"] == 2
    assert malformed_res["counts"]["invalid_findings_skipped"] == 2


def test_benchmark_timing_zap_parser_and_cli_unmeasured_reporting(tmp_path: Path):
    # Kiểm tra tính thời gian trung bình và bỏ qua các lần chạy lỗi thời gian:
    timing = compute_timing_metrics(
        [
            {"duration_seconds": 10.0},
            {"start_time": "2026-11-12T10:00:00+00:00", "end_time": "2026-11-12T10:00:20+00:00"},
            {"start_time": "2026-11-12T10:00:20+00:00", "end_time": "2026-11-12T10:00:10+00:00"},  # âm -> bỏ qua
            {"duration_seconds": -5},  # âm -> bỏ qua
            {},  # thiếu thời gian -> bỏ qua
        ]
    )
    assert timing["measured"] is True
    assert timing["valid_runs_count"] == 2
    assert timing["skipped_runs_count"] == 3
    assert timing["average_duration_seconds"] == pytest.approx(15.0)
    assert timing["min_duration_seconds"] == pytest.approx(10.0)
    assert timing["max_duration_seconds"] == pytest.approx(20.0)

    unmeasured_timing = compute_timing_metrics([])
    assert unmeasured_timing["measured"] is False
    assert unmeasured_timing["status"] == "chưa đo"

    # Kiểm tra đọc định dạng JSON chuẩn của OWASP ZAP:
    zap_raw = {
        "site": [
            {
                "@name": "http://127.0.0.1:3000",
                "alerts": [
                    {
                        "alert": "SQL Injection",
                        "cweid": "89",
                        "instances": [
                            {"uri": "http://127.0.0.1:3000/rest/products/search?q=1", "param": "q"}
                        ],
                    }
                ],
            }
        ]
    }
    parsed_zap = parse_tool_artifact(zap_raw)
    assert len(parsed_zap["findings"]) == 1
    assert extract_matching_key(parsed_zap["findings"][0]) == ("sqli", "/rest/products/search", "q")

    # Kiểm tra CLI xuất báo cáo Markdown ghi rõ "chưa đo" cho công cụ chưa có artifact:
    gt_file = tmp_path / "gt.json"
    scanner_file = tmp_path / "scanner.json"
    out_md = tmp_path / "report.md"

    gt_file.write_text(
        json.dumps(
            {
                "ground_truth": [
                    {"vuln_category": "sqli", "target_url": "http://127.0.0.1:3000/rest/products/search", "parameter": "q"}
                ]
            }
        ),
        encoding="utf-8",
    )
    scanner_file.write_text(
        json.dumps(
            {
                "duration_seconds": 8.4,
                "findings": [
                    {
                        "vuln_name": "SQL Injection (Error-based)",
                        "cwe_id": "CWE-89",
                        "target_url": "http://127.0.0.1:3000/rest/products/search",
                        "parameter": "q",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = benchmark_cli_main(
        [
            "--ground-truth",
            str(gt_file),
            "--scanner-report",
            str(scanner_file),
            "--target-name",
            "Juice Shop Localhost",
            "-o",
            str(out_md),
        ]
    )
    assert exit_code == 0
    md_text = out_md.read_text(encoding="utf-8")
    assert "OWASP Web Scanner (Đề tài) | đã đo | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 8.4s" in md_text
    assert "OWASP ZAP Baseline | **chưa đo**" in md_text


def test_benchmark_cli_with_sample_fixtures_and_partial_inputs(tmp_path: Path):
    """Issue 1: Kiểm tra CLI benchmark/evaluate.py với bộ fixtures mẫu và khi truyền đủ/thiếu từng loại artifact."""
    repo_root = Path(__file__).resolve().parent.parent
    gt_fixture = repo_root / "benchmark" / "fixtures" / "ground_truth_sample.json"
    scanner_fixture = repo_root / "benchmark" / "fixtures" / "scanner_sample.json"
    zap_fixture = repo_root / "benchmark" / "fixtures" / "zap_sample.json"

    assert gt_fixture.is_file()
    assert scanner_fixture.is_file()
    assert zap_fixture.is_file()

    # 1. Chạy với cả --scanner-report và --zap-report từ benchmark/fixtures/:
    out_both = tmp_path / "both.md"
    code_both = benchmark_cli_main(
        [
            "--ground-truth",
            str(gt_fixture),
            "--scanner-report",
            str(scanner_fixture),
            "--zap-report",
            str(zap_fixture),
            "--target-name",
            "Sample Fixture Demo (Synthetic)",
            "-o",
            str(out_both),
        ]
    )
    assert code_both == 0
    md_both = out_both.read_text(encoding="utf-8")
    assert "OWASP Web Scanner (Đề tài) | đã đo | 3 | 0 | 1 | 1.0000 | 0.7500 | 0.8571 | 6.5s" in md_both
    assert "OWASP ZAP Baseline | đã đo | 2 | 0 | 2 | 1.0000 | 0.5000 | 0.6667 | 12.0s" in md_both

    # 2. Chạy chỉ với --scanner-report (ZAP ghi rõ "chưa đo"):
    out_scanner_only = tmp_path / "scanner_only.md"
    code_scanner = benchmark_cli_main(
        [
            "--ground-truth",
            str(gt_fixture),
            "--scanner-report",
            str(scanner_fixture),
            "-o",
            str(out_scanner_only),
        ]
    )
    assert code_scanner == 0
    md_scanner = out_scanner_only.read_text(encoding="utf-8")
    assert "OWASP Web Scanner (Đề tài) | đã đo" in md_scanner
    assert "OWASP ZAP Baseline | **chưa đo**" in md_scanner

    # 3. Chạy chỉ với --zap-report (Scanner ghi rõ "chưa đo"):
    out_zap_only = tmp_path / "zap_only.md"
    code_zap = benchmark_cli_main(
        [
            "--ground-truth",
            str(gt_fixture),
            "--zap-report",
            str(zap_fixture),
            "-o",
            str(out_zap_only),
        ]
    )
    assert code_zap == 0
    md_zap = out_zap_only.read_text(encoding="utf-8")
    assert "OWASP Web Scanner (Đề tài) | **chưa đo**" in md_zap
    assert "OWASP ZAP Baseline | đã đo" in md_zap

    # 4. Chạy không có cả --scanner-report lẫn --zap-report (cả 2 đều ghi rõ "chưa đo"):
    out_none = tmp_path / "none.md"
    code_none = benchmark_cli_main(
        [
            "--ground-truth",
            str(gt_fixture),
            "-o",
            str(out_none),
        ]
    )
    assert code_none == 0
    md_none = out_none.read_text(encoding="utf-8")
    assert "OWASP Web Scanner (Đề tài) | **chưa đo**" in md_none
    assert "OWASP ZAP Baseline | **chưa đo**" in md_none
