"""
Tiện ích nạp danh mục mẫu kiểm thử và cấu hình tiêu chuẩn OWASP (Issue #1.3).
Hỗ trợ đọc các tệp cấu hình theo từng danh mục trong thư mục payloads/
và tra cứu thông tin phân loại CWE / OWASP Top 10.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config.config import Config


class PayloadLoader:
    """
    Bộ nạp dữ liệu cấu hình mẫu kiểm thử và tiêu chuẩn bảo mật từ thư mục payloads/.
    Tự động bỏ qua các dòng trống và dòng chú thích bắt đầu bằng '#'.
    """

    CATEGORY_FILES: dict[str, str] = {
        "security_headers": "headers/security_headers.txt",
        "sqli_error": "sqli/error_based.txt",
        "sqli_boolean": "sqli/boolean_based.txt",
        "sqli_time": "sqli/time_based.txt",
        "xss_html": "xss/html_payloads.txt",
        "xss_js_event": "xss/js_event_payloads.txt",
    }

    def __init__(self, payloads_dir: Path | str | None = None) -> None:
        self.payloads_dir = Path(payloads_dir) if payloads_dir else Config.PAYLOADS_DIR

    def load_lines(self, relative_path: str) -> list[str]:
        """
        Đọc danh sách các dòng cấu hình/mẫu kiểm thử từ tệp văn bản,
        loại bỏ dòng trống và dòng comment (#).
        """
        file_path = self.payloads_dir / relative_path
        if not file_path.exists():
            raise FileNotFoundError(f"Không tìm thấy tệp mẫu kiểm thử: {file_path}")

        lines: list[str] = []
        with file_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(line)
        return lines

    def load_category(self, category: str) -> list[str]:
        """Nạp danh sách mẫu kiểm thử theo tên danh mục định sẵn."""
        if category not in self.CATEGORY_FILES:
            valid_keys = ", ".join(sorted(self.CATEGORY_FILES.keys()))
            raise KeyError(f"Danh mục '{category}' không hợp lệ. Các danh mục hỗ trợ: {valid_keys}")
        return self.load_lines(self.CATEGORY_FILES[category])

    def load_security_headers_spec(self) -> list[dict[str, str]]:
        """
        Đọc đặc tả các HTTP Security Headers từ headers/security_headers.txt.
        Định dạng mỗi dòng: HEADER_NAME | SEVERITY | CWE_ID | RECOMMENDED_VALUE | DESCRIPTION
        """
        raw_lines = self.load_category("security_headers")
        specs: list[dict[str, str]] = []
        for line in raw_lines:
            parts = [part.strip() for part in line.split("|")]
            if len(parts) >= 5:
                specs.append(
                    {
                        "header": parts[0],
                        "severity": parts[1],
                        "cwe_id": parts[2],
                        "recommended": parts[3],
                        "remediation": parts[4],
                    }
                )
        return specs

    def load_owasp_catalog(self) -> dict[str, Any]:
        """Nạp danh mục phân loại chuẩn OWASP Top 10 & CWE từ tệp owasp_catalog.json."""
        catalog_path = self.payloads_dir / "owasp_catalog.json"
        if not catalog_path.exists():
            return {}
        with catalog_path.open("r", encoding="utf-8") as f:
            return json.load(f)
