"""
Dịch vụ quản lý mục tiêu kiểm thử (Target Management) và xác minh quyền sở hữu.
Tuân thủ nghiêm ngặt chính sách kiểm tra phạm vi mục tiêu của `validate_target_url`.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from core.crawler.url_parser import URLParser
from core.security.scope_policy import MAX_SCAN_DEPTH
from core.security.target_validator import validate_target_url
from core.utils.safe_http_client import SafeHTTPClient
from models.scan_job import ScanTarget, TargetAuthorizationStatus

VERIFIED_OR_APPROVED_STATUSES: frozenset[str] = frozenset(
    {
        TargetAuthorizationStatus.VERIFIED.value,
        TargetAuthorizationStatus.APPROVED.value,
    }
)
SUPPORTED_VERIFY_METHODS: frozenset[str] = frozenset({"WELL_KNOWN", "DNS_TXT"})


def _normalize_scope(raw_scope: Any) -> dict[str, Any]:
    if raw_scope is None:
        return {"allowed_paths": ["/"], "max_depth": 2}
    if not isinstance(raw_scope, dict):
        raise ValueError("scope phải là một JSON object.")
    max_depth = raw_scope.get("max_depth", 2)
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not (0 <= max_depth <= MAX_SCAN_DEPTH):
        raise ValueError(f"scope.max_depth phải là số nguyên từ 0 đến {MAX_SCAN_DEPTH}.")

    raw_paths = raw_scope.get("allowed_paths", ["/"])
    if not isinstance(raw_paths, list) or not raw_paths or any(not isinstance(p, str) for p in raw_paths):
        raise ValueError("scope.allowed_paths phải là danh sách chuỗi đường dẫn không rỗng.")
    cleaned_paths: list[str] = []
    for path_item in raw_paths[:20]:
        p = path_item.strip()
        if not p.startswith("/"):
            raise ValueError("Mỗi đường dẫn trong scope.allowed_paths phải bắt đầu bằng '/'.")
        if p not in cleaned_paths:
            cleaned_paths.append(p)
    return {"allowed_paths": cleaned_paths or ["/"], "max_depth": max_depth}


def create_target(
    db: Session,
    *,
    owner_id: int,
    url: str,
    name: str | None = None,
    description: str | None = None,
    scope: Any = None,
    resolve_dns: bool = False,
) -> ScanTarget:
    """
    Khai báo mục tiêu kiểm thử mới trong phạm vi được phép (`localhost` / `AUTHORIZED_TARGET_DOMAINS`).
    Sinh `verification_token` ngẫu nhiên để xác minh quyền sở hữu qua `.well-known` hoặc DNS TXT.
    """
    validated_url = validate_target_url(url, resolve_dns=resolve_dns)
    normalized_url = URLParser.normalize(validated_url)
    parsed = urlsplit(normalized_url)
    resolved_name = (name or "").strip() or (parsed.hostname or normalized_url)
    if len(resolved_name) > 150:
        resolved_name = resolved_name[:150]

    normalized_scope = _normalize_scope(scope)
    clean_desc = description.strip()[:1000] if isinstance(description, str) and description.strip() else None

    target = ScanTarget(
        name=resolved_name,
        url=normalized_url,
        description=clean_desc,
        owner_id=owner_id,
        scope=normalized_scope,
        authorization_status=TargetAuthorizationStatus.PENDING.value,
        verification_token=secrets.token_urlsafe(24),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def list_targets(db: Session, *, user_id: int, is_admin: bool = False, limit: int = 100) -> list[ScanTarget]:
    """Liệt kê mục tiêu của người dùng (hoặc toàn bộ nếu là Admin)."""
    query = db.query(ScanTarget)
    if not is_admin:
        query = query.filter(ScanTarget.owner_id == user_id)
    return query.order_by(ScanTarget.id.desc()).limit(limit).all()


def get_target(
    db: Session,
    target_id: int,
    *,
    user_id: int | None = None,
    is_admin: bool = False,
) -> ScanTarget | None:
    """Truy vấn mục tiêu theo ID kèm kiểm tra quyền sở hữu."""
    query = db.query(ScanTarget).filter(ScanTarget.id == target_id)
    if not is_admin and user_id is not None:
        query = query.filter(ScanTarget.owner_id == user_id)
    return query.first()


def _default_dns_txt_lookup(record_name: str) -> list[str]:
    """Đọc bản ghi DNS TXT nếu môi trường có cài `dnspython`."""
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "Môi trường chưa cài thư viện dnspython để tra cứu DNS TXT; hãy dùng phương thức WELL_KNOWN."
        ) from exc

    answers = dns.resolver.resolve(record_name, "TXT", lifetime=5.0)
    records: list[str] = []
    for rdata in answers:
        strings = getattr(rdata, "strings", None)
        if strings:
            records.append("".join(s.decode("utf-8", errors="ignore") for s in strings))
        else:
            records.append(str(rdata).strip('"'))
    return records


def verify_target_ownership(
    db: Session,
    target_id: int,
    *,
    user_id: int,
    is_admin: bool = False,
    method: str = "WELL_KNOWN",
    http_client: SafeHTTPClient | None = None,
    txt_lookup: Callable[[str], list[str]] | None = None,
) -> ScanTarget:
    """
    Xác minh quyền sở hữu mục tiêu:
    - `WELL_KNOWN`: kiểm tra `<scheme>://<netloc>/.well-known/pentest-verify.txt` chứa `verification_token`.
    - `DNS_TXT`: kiểm tra bản ghi TXT tại `_pentest-verify.<hostname>` chứa `verification_token`.
    """
    normalized_method = (method or "WELL_KNOWN").strip().upper()
    if normalized_method not in SUPPORTED_VERIFY_METHODS:
        raise ValueError(f"Phương thức xác minh không hợp lệ. Chọn: {', '.join(sorted(SUPPORTED_VERIFY_METHODS))}.")

    target = get_target(db, target_id, user_id=user_id, is_admin=is_admin)
    if target is None:
        raise LookupError("Không tìm thấy mục tiêu kiểm thử.")

    if not target.verification_token:
        target.verification_token = secrets.token_urlsafe(24)
        db.commit()
        db.refresh(target)

    token = target.verification_token
    # Đảm bảo URL mục tiêu vẫn tuân thủ nghiêm ngặt chính sách validate_target_url
    validate_target_url(target.url, resolve_dns=(http_client is None and txt_lookup is None))
    parsed = urlsplit(target.url)

    verified = False
    if normalized_method == "WELL_KNOWN":
        verify_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/pentest-verify.txt"
        client = http_client or SafeHTTPClient(timeout=5, max_redirects=0)
        resp = client.get(verify_url, allow_redirects=False)
        if resp is not None and resp.status_code == 200 and token in (resp.text or ""):
            verified = True
    elif normalized_method == "DNS_TXT":
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        lookup_fn = txt_lookup or _default_dns_txt_lookup
        txt_records = lookup_fn(f"_pentest-verify.{hostname}")
        if any(token in rec for rec in txt_records):
            verified = True

    if not verified:
        raise PermissionError(
            f"Không tìm thấy mã xác minh hợp lệ qua phương thức {normalized_method}."
        )

    target.authorization_status = TargetAuthorizationStatus.VERIFIED.value
    target.verification_method = normalized_method
    db.commit()
    db.refresh(target)
    return target


def set_target_approval(
    db: Session,
    target_id: int,
    *,
    approved: bool,
) -> ScanTarget:
    """Quản trị viên phê duyệt hoặc từ chối một mục tiêu đã khai báo."""
    target = db.get(ScanTarget, target_id)
    if target is None:
        raise LookupError("Không tìm thấy mục tiêu kiểm thử.")
    # Vẫn kiểm tra tính hợp lệ URL mục tiêu trước khi phê duyệt
    validate_target_url(target.url, resolve_dns=False)

    if approved:
        target.authorization_status = TargetAuthorizationStatus.APPROVED.value
        target.verification_method = "ADMIN_APPROVED"
    else:
        target.authorization_status = TargetAuthorizationStatus.REJECTED.value
    db.commit()
    db.refresh(target)
    return target


def find_authorized_target_for_scan(
    db: Session,
    *,
    url: str,
    user_id: int,
    is_admin: bool = False,
    target_id: int | None = None,
) -> ScanTarget | None:
    """
    Tìm `ScanTarget` đã được xác minh (`VERIFIED` hoặc `APPROVED`) khớp với URL hoặc Origin của phiên quét.
    """
    normalized_url = URLParser.normalize(url)
    req_parsed = urlsplit(normalized_url)
    req_origin = f"{req_parsed.scheme}://{req_parsed.netloc}"

    if target_id is not None:
        candidate = get_target(db, target_id, user_id=user_id, is_admin=is_admin)
        if candidate is None or candidate.authorization_status not in VERIFIED_OR_APPROVED_STATUSES:
            return None
        cand_parsed = urlsplit(URLParser.normalize(candidate.url))
        if f"{cand_parsed.scheme}://{cand_parsed.netloc}" != req_origin:
            return None
        return candidate

    candidates = list_targets(db, user_id=user_id, is_admin=is_admin, limit=200)
    for item in candidates:
        if item.authorization_status not in VERIFIED_OR_APPROVED_STATUSES:
            continue
        try:
            cand_norm = URLParser.normalize(item.url)
        except ValueError:
            continue
        if cand_norm == normalized_url:
            return item
        cand_parsed = urlsplit(cand_norm)
        if f"{cand_parsed.scheme}://{cand_parsed.netloc}" == req_origin:
            return item
    return None
