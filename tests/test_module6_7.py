"""
Kiểm thử tích hợp và đơn vị cho:
- Module 6.1: Giao diện Web Dashboard, trang chi tiết Scan, bảo mật DOM/XSS và lưu trữ JWT.
- Module 6.2: API tải báo cáo kỹ thuật TXT/PDF (`GET /api/scans/<id>/report?format=pdf|txt`), phân quyền chủ sở hữu, escape ký tự HTML/XML đặc biệt.
- Module 7.1 & 7.2: Công cụ tính toán chỉ số thực nghiệm (TP, FP, FN, Precision, Recall, F1-Score, thời gian quét trung bình), deduplication, mẫu số bằng 0, parser OWASP ZAP artifact và CLI.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from app import create_app
from benchmark.evaluate import (
    MatchingConfig,
    compare_tools,
    compute_classification_metrics,
    compute_timing_metrics,
    extract_matching_key,
    main as benchmark_cli_main,
    normalize_endpoint_path,
    normalize_vuln_category,
    parse_tool_artifact,
    render_benchmark_markdown,
)
from models.base import Base
from models.scan_job import CrawledEndpoint, ScanStatus
from models.user import User
from models.vulnerability import VulnerabilityFinding
from services import scan_service


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


def _seed_completed_scan_with_special_chars(client, user_id: int) -> int:
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
                vuln_type="SQL Injection (Error-based) <tag>&\"'",
                severity="HIGH",
                target_url="http://127.0.0.1:8080/search?q=1",
                param="q",
                payload="1' OR '1'='1 -- <script>alert(1)</script>&\"'",
                evidence="MySQL error near '<svg onload=alert(1)>' & \"quote\"",
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
                remediation="Sử dụng Prepared Statements / Parameterized Queries.",
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
                remediation="Mã hóa HTML entity trước khi phản chiếu dữ liệu.",
            )
        )
        db.commit()
        return scan.id


# ==============================================================================
# MODULE 6.1 — WEB DASHBOARD ROUTES & FRONTEND ASSETS
# ==============================================================================


def test_dashboard_and_scan_detail_pages_render_and_static_assets_safe(client):
    """Kiểm tra route giao diện Dashboard, Scan Detail và tài nguyên JS/CSS hoạt động đúng."""
    for path in ("/", "/dashboard"):
        resp = client.get(path)
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "newScanForm" in html
        assert "severityChart" in html
        assert "scansTable" in html
        assert "/static/js/app.js" in html
        assert "/static/js/chart.js" in html

    detail_resp = client.get("/scans/42")
    assert detail_resp.status_code == 200
    detail_html = detail_resp.get_data(as_text=True)
    assert 'data-session-id="42"' in detail_html
    assert "findingDetailModal" in detail_html
    assert "stopScanBtn" in detail_html
    assert "downloadTxtBtn" in detail_html
    assert "downloadPdfBtn" in detail_html

    # Kiểm tra file static JS không dùng innerHTML bất cẩn và không log JWT:
    app_js = client.get("/static/js/app.js").get_data(as_text=True)
    assert "textContent" in app_js
    assert "innerHTML =" not in app_js
    assert "console.log" not in app_js


# ==============================================================================
# MODULE 6.2 — TECHNICAL REPORT DOWNLOAD API (TXT & PDF)
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


def test_report_endpoint_txt_and_pdf_success_with_xml_special_chars(client):
    owner_id, owner_headers = _register_and_login(client, "owner3", "owner3@example.test")
    scan_id = _seed_completed_scan_with_special_chars(client, owner_id)

    # Xuất TXT thành công
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
    assert "Prepared Statements" in txt_body

    # Xuất PDF thành công (hoặc skip rõ lý do nếu thiếu reportlab)
    pytest.importorskip("reportlab", reason="Thư viện reportlab chưa được cài đặt để kiểm thử xuất PDF.")
    pdf_resp = client.get(f"/api/scans/{scan_id}/report?format=pdf", headers=owner_headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.content_type == "application/pdf"
    assert f'filename="scan-report-{scan_id}.pdf"' in pdf_resp.headers.get("Content-Disposition", "")
    pdf_bytes = pdf_resp.get_data()
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500


# ==============================================================================
# MODULE 7.1 & 7.2 — BENCHMARK EVALUATION & METRICS UNIT TESTS (OFFLINE)
# ==============================================================================


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
        [{"vuln_category": "sqli", "target_url": "http://127.0.0.1:4280/ vuln", "parameter": "id"}],
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
