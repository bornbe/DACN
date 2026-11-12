"""
Gói Scanner: BaseScanner, Finding và bộ đăng ký (registry) các module kiểm thử.
Các scanner được nạp lười (lazy) để module chưa hoàn thiện hoặc bị vô hiệu hóa vì lý do
an toàn không làm hỏng toàn bộ hệ thống.
"""

from __future__ import annotations

import importlib
import inspect

from core.scanners.base_scanner import SEVERITY_ORDER, BaseScanner, Finding
from core.scanners.ssrf_scanner import UNSUPPORTED_SSRF_MESSAGE

# Tên module chính thức được hỗ trợ -> (đường dẫn module Python, tên lớp mong đợi)
SCANNER_REGISTRY: dict[str, tuple[str, str]] = {
    "headers": ("core.scanners.security_headers_scanner", "SecurityHeadersScanner"),
    "csrf": ("core.scanners.csrf_scanner", "CSRFScanner"),
    "sqli": ("core.scanners.sqli_scanner", "SQLiScanner"),
    "xss": ("core.scanners.xss_scanner", "XSSScanner"),
}

# Các module đã lên kế hoạch trong tài liệu gốc nhưng bị vô hiệu hóa / chưa hỗ trợ vì giới hạn an toàn Lab
UNSUPPORTED_MODULES: dict[str, str] = {
    "ssrf": UNSUPPORTED_SSRF_MESSAGE,
}

ALL_MODULES: tuple[str, ...] = tuple(SCANNER_REGISTRY)


def load_scanner_class(module_key: str) -> type[BaseScanner]:
    """
    Nạp lớp scanner theo tên module. Nếu không có đúng tên lớp mong đợi, dùng lớp con
    BaseScanner đầu tiên định nghĩa trong module. Ném ImportError/LookupError nếu không có
    hoặc nếu lớp bị đánh dấu `enabled = False`.
    """
    if module_key not in SCANNER_REGISTRY:
        if module_key in UNSUPPORTED_MODULES:
            raise LookupError(UNSUPPORTED_MODULES[module_key])
        raise KeyError(f"Module quét không hợp lệ: '{module_key}'")
    module_path, class_name = SCANNER_REGISTRY[module_key]
    module = importlib.import_module(module_path)

    candidate = getattr(module, class_name, None)
    if inspect.isclass(candidate) and issubclass(candidate, BaseScanner):
        if getattr(candidate, "enabled", True) is False:
            raise LookupError(f"Module '{module_key}' đã bị vô hiệu hóa vì lý do an toàn.")
        return candidate
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, BaseScanner) and obj is not BaseScanner and obj.__module__ == module.__name__:
            if getattr(obj, "enabled", True) is False:
                raise LookupError(f"Module '{module_key}' đã bị vô hiệu hóa vì lý do an toàn.")
            return obj
    raise LookupError(f"Module '{module_path}' chưa định nghĩa lớp con của BaseScanner.")


__all__ = [
    "ALL_MODULES",
    "SCANNER_REGISTRY",
    "SEVERITY_ORDER",
    "UNSUPPORTED_MODULES",
    "BaseScanner",
    "Finding",
    "load_scanner_class",
]
