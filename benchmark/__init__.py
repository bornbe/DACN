"""
Gói công cụ đánh giá thực nghiệm (Benchmark) cho OWASP Web Scanner.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "MatchingConfig",
    "build_parser",
    "compare_tools",
    "compute_classification_metrics",
    "compute_timing_metrics",
    "extract_cwe_codes",
    "extract_matching_key",
    "main",
    "normalize_cwe_id",
    "normalize_endpoint_path",
    "normalize_vuln_category",
    "parse_tool_artifact",
    "render_benchmark_markdown",
]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from benchmark import evaluate

        return getattr(evaluate, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
