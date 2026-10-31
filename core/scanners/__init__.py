"""
Gói Scanner: BaseScanner, Finding và bộ đăng ký (registry) các module kiểm thử.
Các scanner được nạp lười (lazy) để module chưa hoàn thiện (ví dụ SQLi, XSS) không làm
hỏng toàn bộ hệ thống: Engine sẽ bỏ qua và cảnh báo thay vì dừng.
"""

from __future__ import annotations

import importlib
import inspect

from core.scanners.base_scanner import SEVERITY_ORDER, BaseScanner, Finding

# Tên module CLI -> (đường dẫn module Python, tên lớp mong đợi)
SCANNER_REGISTRY: dict[str, tuple[str, str]] = {
    "headers": ("core.scanners.security_headers_scanner", "SecurityHeadersScanner"),
    "csrf": ("core.scanners.csrf_scanner", "CSRFScanner"),
    "sqli": ("core.scanners.sqli_scanner", "SQLiScanner"),
    "xss": ("core.scanners.xss_scanner", "XSSScanner"),
}

ALL_MODULES: tuple[str, ...] = tuple(SCANNER_REGISTRY)


def load_scanner_class(module_key: str) -> type[BaseScanner]:
    """
    Nạp lớp scanner theo tên module. Nếu không có đúng tên lớp mong đợi, dùng lớp con
    BaseScanner đầu tiên định nghĩa trong module. Ném ImportError/LookupError nếu không có.
    """
    if module_key not in SCANNER_REGISTRY:
        raise KeyError(f"Module quét không hợp lệ: '{module_key}'")
    module_path, class_name = SCANNER_REGISTRY[module_key]
    module = importlib.import_module(module_path)

    candidate = getattr(module, class_name, None)
    if inspect.isclass(candidate) and issubclass(candidate, BaseScanner):
        return candidate
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, BaseScanner) and obj is not BaseScanner and obj.__module__ == module.__name__:
            return obj
    raise LookupError(f"Module '{module_path}' chưa định nghĩa lớp con của BaseScanner.")


__all__ = [
    "ALL_MODULES",
    "SCANNER_REGISTRY",
    "SEVERITY_ORDER",
    "BaseScanner",
    "Finding",
    "load_scanner_class",
]
