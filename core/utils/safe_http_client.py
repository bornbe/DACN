"""
SafeHTTPClient: Lớp bọc (wrapper) an toàn quanh `requests.Session` - Yêu cầu #2.

Quy trình bảo vệ 4 bước trên mỗi HTTP request và mỗi bước chuyển hướng (Redirect):
1. Xác thực URL theo chính sách Loopback (`validate_target_url`) và phân giải DNS bước 1.
2. Phân giải và xác minh lại IP ngay trước khi kết nối socket (chống DNS Rebinding TOCTOU).
3. Gắn cố định header `Host` (Header Pinning) và cưỡng bức `allow_redirects=False`, không cho phép `verify=False`.
4. Nếu có phản hồi 3xx kèm `Location`, kiểm tra lại đích redirect theo chính sách Loopback + Scope trước khi theo tiếp.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import requests

from config.config import Config
from core.security.dns_resolver import DNSResolutionError, ResolverFunc, resolve_hostname
from core.security.scope_policy import validate_redirect_target
from core.security.target_validator import (
    SSRFBlockedError,
    TargetValidationError,
    validate_resolved_ips,
    validate_target_url,
)

DEFAULT_MAX_REDIRECTS = 5


class SafeHTTPClient:
    """
    HTTP Client an toàn dùng cho môi trường Lab:
    - Chặn tuyệt đối kết nối ngoài loopback/localhost.
    - Chặn DNS Rebinding (kiểm tra DNS trước và ngay khi chuẩn bị gửi request).
    - Tự kiểm soát từng hop redirect với `allow_redirects=False`.
    - Cấm vô hiệu hóa xác minh chứng chỉ TLS (`verify=False`).
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int | float | None = None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        user_agent: str = "OWASP-Scanner-SafeHTTP/1.0",
        resolver: ResolverFunc | None = None,
    ) -> None:
        self.session: requests.Session = session or requests.Session()
        self.timeout: int | float = (
            timeout if timeout is not None else Config.DEFAULT_REQUEST_TIMEOUT
        )
        self.max_redirects: int = max(0, int(max_redirects))
        self.resolver: ResolverFunc | None = resolver
        self.session.headers.setdefault("User-Agent", user_agent)

    def _verify_pre_connect_dns(self, url: str) -> str:
        """
        Bước 2: Phân giải DNS lần thứ hai ngay trước khi tạo kết nối để phát hiện DNS Rebinding
        (trường hợp lần phân giải đầu trả về 127.0.0.1 nhưng lần kết nối thực tế đổi sang IP khác).
        """
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        try:
            ips = resolve_hostname(hostname, resolver=self.resolver)
        except DNSResolutionError as exc:
            raise SSRFBlockedError(
                "Không thể phân giải DNS an toàn trước khi kết nối."
            ) from exc
        validate_resolved_ips(hostname, ips)
        return parsed.netloc

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Thực thi HTTP request an toàn. Ném `SSRFBlockedError` / `TargetValidationError`
        nếu URL ban đầu, DNS hoặc bất kỳ bước redirect nào vi phạm chính sách.
        """
        if kwargs.get("verify") is False:
            raise TargetValidationError(
                "Không cho phép tắt xác minh chứng chỉ TLS (verify=False)."
            )

        # Bước 1: Xác thực URL gốc và kiểm tra DNS ban đầu
        validate_target_url(url, resolve_dns=True, resolver=self.resolver)

        kwargs.setdefault("timeout", self.timeout)
        kwargs["allow_redirects"] = False

        current_method = (method or "GET").upper()
        current_url = url

        for hop in range(self.max_redirects + 1):
            # Bước 2: Kiểm tra chống DNS Rebinding ngay trước khi gửi request
            netloc = self._verify_pre_connect_dns(current_url)

            # Bước 3: Pinning header Host và gửi request với allow_redirects=False
            req_headers = dict(kwargs.get("headers") or {})
            req_headers.setdefault("Host", netloc)
            kwargs["headers"] = req_headers

            response = self.session.request(current_method, current_url, **kwargs)

            location = response.headers.get("Location")
            if not allow_redirects or not (300 <= response.status_code < 400) or not location:
                return response

            if hop >= self.max_redirects:
                raise SSRFBlockedError(
                    f"Vượt quá số lần chuyển hướng tối đa ({self.max_redirects}) tại {url}."
                )

            # Bước 4: Xác thực đích redirect theo chính sách Loopback + Scope gốc
            target_url = validate_redirect_target(
                origin_url=url,
                current_url=current_url,
                location_header=location,
                resolve_dns=True,
                resolver=self.resolver,
            )

            if response.status_code == 303 or (
                response.status_code in (301, 302) and current_method not in ("GET", "HEAD")
            ):
                current_method = "HEAD" if current_method == "HEAD" else "GET"
                for body_key in ("data", "json", "files"):
                    kwargs.pop(body_key, None)
            kwargs.pop("params", None)
            current_url = target_url

        raise SSRFBlockedError(f"Vượt quá số lần chuyển hướng tối đa ({self.max_redirects}).")

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)
