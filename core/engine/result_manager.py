"""
Quản lý kết quả quét: lọc trùng lặp Finding (Deduplication), thống kê mức độ nghiêm trọng
và lưu trữ vào CSDL. Các trường nhạy cảm tự động được mã hóa AES-256-GCM At-Rest
thông qua kiểu EncryptedText của các ORM model (Issue #1.2).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from core.crawler.form_parser import EndpointDescriptor
from core.scanners.base_scanner import SEVERITY_ORDER, Finding
from models.scan_job import CrawledEndpoint
from models.vulnerability import VulnerabilityFinding


class ResultManager:
    """Thu thập Finding, loại bỏ trùng lặp theo (loại lỗ hổng, URL, tham số)."""

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._keys: set[tuple[str, str, str]] = set()

    def add(self, finding: Finding) -> bool:
        """Thêm Finding; trả về False nếu là bản trùng lặp và bị bỏ qua."""
        key = finding.dedup_key()
        if key in self._keys:
            return False
        self._keys.add(key)
        self._findings.append(finding)
        return True

    @property
    def findings(self) -> list[Finding]:
        """Danh sách Finding đã sắp xếp theo mức độ nghiêm trọng giảm dần."""
        order = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}
        return sorted(self._findings, key=lambda f: (order.get(f.severity, 99), f.vuln_name, f.target_url))

    def severity_counts(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self._findings:
            counts[finding.severity] += 1
        return counts

    def build_summary(self, total_endpoints: int, pages_crawled: int = 0) -> dict[str, Any]:
        """Dữ liệu thống kê tương thích với trường ScanSession.summary_stats."""
        return {
            "total_endpoints": total_endpoints,
            "pages_crawled": pages_crawled,
            "total_findings": len(self._findings),
            "severity_counts": self.severity_counts(),
        }

    def persist_findings(self, db: Session, session_id: int) -> int:
        """Lưu toàn bộ Finding vào CSDL (có mã hóa At-Rest). Trả về số bản ghi đã lưu."""
        for f in self.findings:
            db.add(
                VulnerabilityFinding(
                    session_id=session_id,
                    vuln_type=f.vuln_name,
                    severity=f.severity,
                    target_url=f.target_url,
                    param=f.parameter,
                    payload=f.payload,
                    evidence=f.evidence,
                    cwe_id=f.cwe_id,
                    owasp_category=f.owasp_category,
                    remediation=f.remediation,
                )
            )
        db.commit()
        return len(self._findings)

    @staticmethod
    def persist_endpoints(db: Session, session_id: int, endpoints: list[EndpointDescriptor]) -> int:
        """Lưu các endpoint thu thập được (URL được mã hóa At-Rest)."""
        for ep in endpoints:
            db.add(
                CrawledEndpoint(
                    session_id=session_id,
                    url=ep.url,
                    method=ep.method,
                    depth=ep.depth,
                    params_schema=ep.params_schema,
                )
            )
        db.commit()
        return len(endpoints)
