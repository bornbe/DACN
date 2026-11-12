"""
Module SSRF Scanner - Trạng thái: VÔ HIỆU HÓA (DISABLED / UNSUPPORTED) theo Chính sách An toàn Lab.

Lý do kỹ thuật & an toàn:
Đặc tả ban đầu tại `Docs/owasp_scanner_web_fake.txt` mô tả SSRF Scanner theo cơ chế Out-of-Band (OOB)
sử dụng dịch vụ callback bên ngoài (Interactsh/webhook). Tuy nhiên, chính sách an toàn bắt buộc của
dự án giới hạn mọi kết nối mạng vào `localhost` / `127.0.0.0/8` / `::1` và nghiêm cấm gọi dịch vụ
bên ngoài hoặc gửi payload thăm dò mạng nội bộ/cloud metadata.

Vì vậy, module này được đánh dấu rõ ràng là `UNSUPPORTED` và không đăng ký vào `SCANNER_REGISTRY`.
Mọi lời gọi trực tiếp tới `SSRFScanner` đều từ chối thực thi và không gửi bất kỳ HTTP request nào.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.scanners.base_scanner import BaseScanner, Finding

if TYPE_CHECKING:
    from core.crawler.form_parser import EndpointDescriptor

UNSUPPORTED_SSRF_MESSAGE = (
    "Module 'ssrf' (Out-of-Band / Interactsh webhook) bị vô hiệu hóa theo chính sách an toàn Lab: "
    "hệ thống chỉ cho phép kết nối loopback cục bộ và nghiêm cấm mọi callback ra mạng ngoài."
)


class SSRFScannerUnsupportedError(RuntimeError):
    """Ngoại lệ khi gọi module SSRF OOB đã bị vô hiệu hóa vì giới hạn an toàn."""


class SSRFScanner(BaseScanner):
    """
    Placeholder an toàn cho SSRF Scanner (Disabled/Unsupported).
    Không kế thừa quy trình gửi payload OOB và tuyệt đối không phát sinh lưu lượng mạng.
    """

    category = "ssrf"
    name = "ssrf"
    enabled = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def scan(self, endpoint: "EndpointDescriptor") -> list[Finding]:
        raise SSRFScannerUnsupportedError(UNSUPPORTED_SSRF_MESSAGE)
