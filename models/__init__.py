"""
Package tập hợp toàn bộ các ORM Entities của hệ thống OWASP Web Scanner.
"""

from models.audit_log import AuditLog
from models.base import (
    Base,
    TimestampMixin,
    get_db_session,
    get_engine,
    get_session_factory,
    init_db,
)
from models.report import Report
from models.scan_job import (
    CrawledEndpoint,
    ScanJob,
    ScanSession,
    ScanStatus,
    ScanTarget,
    TargetAuthorizationStatus,
)
from models.user import VALID_ROLES, User, normalize_role_alias
from models.vulnerability import SeverityLevel, Vulnerability, VulnerabilityFinding

__all__ = [
    "Base",
    "TimestampMixin",
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "init_db",
    "User",
    "VALID_ROLES",
    "normalize_role_alias",
    "ScanTarget",
    "TargetAuthorizationStatus",
    "ScanSession",
    "ScanJob",
    "ScanStatus",
    "CrawledEndpoint",
    "VulnerabilityFinding",
    "Vulnerability",
    "SeverityLevel",
    "AuditLog",
    "Report",
]
