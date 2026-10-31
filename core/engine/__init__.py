"""
Gói Engine: điều phối quét, ngữ cảnh quét và quản lý kết quả (Module 4).
"""

from core.engine.result_manager import ResultManager
from core.engine.scan_context import ScanCancelled, ScanContext
from core.engine.scan_engine import ScanEngine, ScanReport, normalize_modules

__all__ = [
    "ResultManager",
    "ScanCancelled",
    "ScanContext",
    "ScanEngine",
    "ScanReport",
    "normalize_modules",
]
