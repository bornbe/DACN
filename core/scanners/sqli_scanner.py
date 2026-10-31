"""
Issue #3.4
Scanner dò SQL Injection bằng phản hồi lỗi CSDL và so sánh điều kiện boolean.
Chỉ gửi probe chẩn đoán an toàn, không truy xuất dữ liệu.
"""

from __future__ import annotations

import difflib
import re
from typing import TYPE_CHECKING, Any

import requests

from core.scanners.base_scanner import BaseScanner, Finding
from core.utils.logger import get_logger

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

logger = get_logger(__name__)

ERROR_PROBES: tuple[str, ...] = ("'", '"')
BOOLEAN_PROBE_PAIRS: tuple[tuple[str, str], ...] = (
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1", "' AND '1'='2"),
)
TRUE_SIMILARITY_THRESHOLD = 0.9
FALSE_SIMILARITY_THRESHOLD = 0.8
SIMILARITY_GAP_THRESHOLD = 0.15

FALLBACK_ERROR_SIGNATURES: tuple[str, ...] = (
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"You have an error in your SQL syntax",
    r"PostgreSQL.*ERROR",
    r"ERROR:\s+syntax error at or near",
    r"psycopg2\..*Error",
    r"Driver.*SQL[\-_\ ]*Server",
    r"SQL Server.*Driver",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near",
    r"ORA-[0-9]{5}",
    r"SQLite/JDBCDriver",
    r"sqlite3\.OperationalError",
    r"SQLite.*(?:syntax error|error)",
    r"near .+: syntax error",
)


class SQLiScanner(BaseScanner):
    """Phát hiện dấu hiệu SQL Injection mà không thực thi truy vấn lấy dữ liệu."""

    category = "sqli"
    name = "sqli"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._error_signatures = self._load_error_signatures()

    def _load_error_signatures(self) -> tuple[re.Pattern[str], ...]:
        signatures = list(FALLBACK_ERROR_SIGNATURES)
        try:
            catalog = self.payload_loader.load_owasp_catalog()
            category = catalog.get("categories", {}).get(self.category, {})
            signatures = list(category.get("error_signatures", [])) + signatures
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            logger.warning("Không nạp được signatures SQLi từ catalog: %s", exc)

        compiled: list[re.Pattern[str]] = []
        seen: set[str] = set()
        for signature in signatures:
            if not isinstance(signature, str) or signature in seen:
                continue
            seen.add(signature)
            try:
                compiled.append(re.compile(signature, re.IGNORECASE | re.DOTALL))
            except re.error as exc:
                logger.warning("Bỏ qua SQLi error signature không hợp lệ '%s': %s", signature, exc)
        return tuple(compiled)

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        """Kiểm tra từng tham số bằng probe lỗi cú pháp và cặp điều kiện boolean."""
        method = endpoint.method.upper()
        if method not in ("GET", "POST") or not endpoint.params:
            return []

        findings: list[Finding] = []
        for parameter, original_value in endpoint.params.items():
            baseline = self._send_values(endpoint.url, method, dict(endpoint.params))
            if baseline is None:
                return []

            error_finding: Finding | None = None
            for probe in ERROR_PROBES:
                values = dict(endpoint.params)
                values[parameter] = f"{original_value}{probe}"
                response = self._send_values(endpoint.url, method, values)
                if response is None:
                    return []
                error = self._find_error(response.text)
                if error is not None:
                    excerpt, signature = error
                    error_finding = self.make_finding(
                        vuln_name="SQL Injection (Error-based)",
                        target_url=endpoint.url,
                        severity="HIGH",
                        parameter=parameter,
                        payload=values[parameter],
                        evidence=f"Khớp signature '{signature}': {excerpt}",
                    )
                    break
            if error_finding is not None:
                findings.append(error_finding)

            boolean_finding, completed = self._check_boolean(
                endpoint.url, method, endpoint.params, parameter, original_value, baseline.text
            )
            if not completed:
                return []
            if boolean_finding is not None:
                findings.append(boolean_finding)
        return findings

    def _send_values(self, url: str, method: str, values: dict[str, str]) -> requests.Response | None:
        """Gửi cùng bộ tham số qua query string hoặc form body tùy method."""
        argument = "params" if method == "GET" else "data"
        return self.send(method, url, **{argument: values})

    def _find_error(self, body: str) -> tuple[str, str] | None:
        for signature in self._error_signatures:
            match = signature.search(body)
            if match is None:
                continue
            excerpt = match.group(0)
            if len(excerpt) > 300:
                excerpt = f"{excerpt[:140]} ... {excerpt[-140:]}"
            return excerpt, signature.pattern
        return None

    def _check_boolean(
        self,
        url: str,
        method: str,
        original_params: dict[str, str],
        parameter: str,
        original_value: str,
        baseline_body: str,
    ) -> tuple[Finding | None, bool]:
        for true_suffix, false_suffix in BOOLEAN_PROBE_PAIRS:
            true_value = f"{original_value}{true_suffix}"
            false_value = f"{original_value}{false_suffix}"
            true_params = dict(original_params)
            false_params = dict(original_params)
            true_params[parameter] = true_value
            false_params[parameter] = false_value

            true_response = self._send_values(url, method, true_params)
            if true_response is None:
                return None, False
            false_response = self._send_values(url, method, false_params)
            if false_response is None:
                return None, False

            true_ratio = difflib.SequenceMatcher(None, baseline_body, true_response.text).ratio()
            false_ratio = difflib.SequenceMatcher(None, baseline_body, false_response.text).ratio()
            if (
                true_ratio >= TRUE_SIMILARITY_THRESHOLD
                and false_ratio <= FALSE_SIMILARITY_THRESHOLD
                and true_ratio - false_ratio >= SIMILARITY_GAP_THRESHOLD
            ):
                return self.make_finding(
                    vuln_name="SQL Injection (Boolean-based)",
                    target_url=url,
                    severity="HIGH",
                    parameter=parameter,
                    payload=f"TRUE: {true_value} | FALSE: {false_value}",
                    evidence=(
                        "Phản hồi TRUE tương đồng với baseline "
                        f"({true_ratio:.3f}); phản hồi FALSE khác biệt ({false_ratio:.3f})."
                    ),
                ), True
        return None, True