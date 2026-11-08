"""
Che dữ liệu nhạy cảm (Authorization, Cookie, token, mật khẩu, JWT...) trong evidence
trước khi lưu trữ hoặc xuất báo cáo.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# Header Authorization / Proxy-Authorization: che toàn bộ giá trị đến hết dòng.
_AUTH_RE = re.compile(r"(?i)((?:proxy-)?authorization\s*[:=]\s*)[^\r\n<]+")
# Header Set-Cookie / Cookie: che toàn bộ giá trị đến hết dòng.
_COOKIE_RE = re.compile(r"(?i)((?<![\w-])(?:set-)?cookie\s*[:=]\s*)[^\r\n<]+")
# Khóa nhạy cảm dạng JSON / query / form / assignment.
_KEY_VALUE_RE = re.compile(
    r"""(?ix)
    (?P<key>["']?[\w-]*(?:token|secret|password|passwd|jwt|api_?key)[\w-]*["']?\s*[:=]\s*)
    (?:
        (?P<dq>")(?:[^"\\]|\\.)*"
      | (?P<sq>')(?:[^'\\]|\\.)*'
      | [^\s&;,"'<>})\]]+
    )
    """
)
# Chuỗi định dạng JWT.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def _kv_replace(match: re.Match[str]) -> str:
    quote = match.group("dq") or match.group("sq") or ""
    return f"{match.group('key')}{quote}{REDACTED}{quote}"


def mask_sensitive_data(text: str | None) -> str | None:
    """Thay các giá trị bí mật trong `text` bằng `[REDACTED]`. Idempotent; None giữ nguyên."""
    if not text:
        return text
    text = _AUTH_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _COOKIE_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _KEY_VALUE_RE.sub(_kv_replace, text)
    return _JWT_RE.sub(REDACTED, text)
