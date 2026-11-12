"""
Công cụ tính toán chỉ số đánh giá thực nghiệm (TP, FP, FN, Precision, Recall, F1-Score,
Thời gian quét trung bình) và đối chứng với OWASP ZAP từ tệp artifact thực tế - Issue #7.1/#7.2.

Nguyên tắc:
- Không tự động gửi request mạng hay khởi chạy container.
- Không bịa đặt số liệu thực nghiệm; chỉ tính toán từ tệp dữ liệu đầu vào có thể kiểm chứng.
- Nếu thiếu dữ liệu chạy thực tế (ví dụ chưa có artifact của ZAP), báo rõ trạng thái "chưa đo".
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Bảng ánh xạ từ khóa tên lỗ hổng / mã CWE về nhóm chuẩn hóa để so khớp giữa Scanner và OWASP ZAP
_CATEGORY_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sql injection", "sqli", "cwe-89", "89")),
    ("xss", ("cross-site scripting", "xss", "input reflection", "cwe-79", "79")),
    ("csrf", ("anti-csrf", "csrf", "cross-site request forgery", "cwe-352", "352")),
    (
        "headers",
        (
            "security header",
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "clickjacking",
            "hsts",
            "csp",
            "cwe-693",
            "cwe-1021",
            "cwe-16",
            "693",
            "1021",
        ),
    ),
)


@dataclass(frozen=True)
class MatchingConfig:
    """
    Cấu hình quy tắc so khớp (Matching Rule) giữa Ground Truth và kết quả phát hiện của công cụ:
    - `match_parameter`: nếu True, yêu cầu khớp cả tên tham số (trừ các nhóm trong `ignore_param_for_categories`).
    - `normalize_host`: nếu True, chuẩn hóa theo đường dẫn URL (`path`) để so khớp nhất quán giữa
      `http://127.0.0.1:3000/rest/products/search` và `http://localhost:3000/rest/products/search`.
    - `ignore_param_for_categories`: các nhóm lỗ hổng cấp trang/header (như `headers`) không phân biệt parameter.
    """

    match_parameter: bool = True
    normalize_host: bool = True
    ignore_param_for_categories: frozenset[str] = field(
        default_factory=lambda: frozenset({"headers"})
    )


def normalize_vuln_category(raw_type: Any, cwe_id: Any = None) -> str:
    """Chuẩn hóa tên lỗ hổng hoặc CWE ID về nhóm chuẩn (`sqli`, `xss`, `csrf`, `headers`...)."""
    text = f"{raw_type or ''} {cwe_id or ''}".strip().lower()
    if not text:
        return ""
    for canonical, keywords in _CATEGORY_ALIASES:
        if any(kw in text for kw in keywords):
            return canonical
    return " ".join(str(raw_type or "").strip().lower().split())


def normalize_endpoint_path(raw_url: Any, normalize_host: bool = True) -> str:
    """
    Chuẩn hóa URL hoặc đường dẫn endpoint:
    - Bỏ query string và fragment.
    - Chuẩn hóa đường dẫn trống thành `/`, bỏ dấu `/` dư ở cuối (trừ `/`).
    - Nếu `normalize_host=False`, giữ cả `scheme://netloc/path`.
    """
    if not isinstance(raw_url, str) or not raw_url.strip():
        return ""
    raw = raw_url.strip()
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1:
        path = path.rstrip("/")

    if normalize_host or not parsed.netloc:
        return path

    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    return f"{scheme}://{netloc}{path}"


def extract_matching_key(
    item: dict[str, Any],
    config: MatchingConfig | None = None,
) -> tuple[str, str, str]:
    """
    Trích xuất khóa đối sánh `(vuln_category, endpoint, parameter)` từ một bản ghi finding hoặc ground truth.
    Ném `ValueError` nếu bản ghi không phải dict hoặc thiếu thông tin bắt buộc (`vuln_category` hoặc `endpoint`).
    """
    if not isinstance(item, dict):
        raise ValueError("Mỗi bản ghi finding/ground truth phải là một dict.")
    cfg = config or MatchingConfig()

    raw_vuln = (
        item.get("vuln_category")
        or item.get("vuln_name")
        or item.get("vuln_type")
        or item.get("alert")
        or item.get("name")
    )
    raw_cwe = item.get("cwe_id") or item.get("cweid")
    category = normalize_vuln_category(raw_vuln, raw_cwe)

    raw_url = (
        item.get("target_url")
        or item.get("url")
        or item.get("uri")
        or item.get("endpoint")
        or item.get("path")
    )
    endpoint = normalize_endpoint_path(raw_url, normalize_host=cfg.normalize_host)

    if not category or not endpoint:
        raise ValueError(f"Bản ghi thiếu loại lỗ hổng hoặc URL/endpoint hợp lệ: {item!r}")

    if not cfg.match_parameter or category in cfg.ignore_param_for_categories:
        param = ""
    else:
        raw_param = item.get("parameter")
        if raw_param is None:
            raw_param = item.get("param")
        param = str(raw_param or "").strip().lower()

    return (category, endpoint, param)


def parse_tool_artifact(data: dict[str, Any]) -> dict[str, Any]:
    """
    Đọc cấu trúc dữ liệu báo cáo từ:
    1. Báo cáo JSON của OWASP Scanner (`findings` + `duration_seconds` / `start_time` / `end_time`).
    2. Báo cáo JSON chuẩn của OWASP ZAP (`site[].alerts[].instances[]`).
    Trả về dict chuẩn hóa gồm `findings`, `duration_seconds`, `start_time`, `end_time`, `metadata`.
    """
    if not isinstance(data, dict):
        raise ValueError("Dữ liệu artifact phải là một JSON object (dict).")

    findings: list[dict[str, Any]] = []
    if isinstance(data.get("findings"), list):
        for item in data["findings"]:
            if isinstance(item, dict):
                findings.append(item)
    elif isinstance(data.get("site"), list):
        # Định dạng xuất JSON chuẩn của OWASP ZAP
        for site in data["site"]:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts", []) or []:
                if not isinstance(alert, dict):
                    continue
                alert_name = alert.get("alert") or alert.get("name") or ""
                cwe_id = f"CWE-{alert['cweid']}" if alert.get("cweid") else None
                instances = alert.get("instances") or [{}]
                for inst in instances:
                    if not isinstance(inst, dict):
                        continue
                    findings.append(
                        {
                            "vuln_name": alert_name,
                            "cwe_id": cwe_id,
                            "target_url": inst.get("uri") or site.get("@name") or "",
                            "parameter": inst.get("param") or "",
                        }
                    )

    return {
        "findings": findings,
        "duration_seconds": data.get("duration_seconds"),
        "start_time": data.get("start_time"),
        "end_time": data.get("end_time"),
        "metadata": data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
    }


def compute_classification_metrics(
    ground_truth: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    config: MatchingConfig | None = None,
) -> dict[str, Any]:
    """
    Tính TP, FP, FN và các chỉ số khoa học Precision, Recall, F1-Score:
      Precision = TP / (TP + FP)
      Recall    = TP / (TP + FN)
      F1-Score  = 2 * (Precision * Recall) / (Precision + Recall)
    - Xử lý an toàn khi mẫu số bằng 0 (trả 0.0).
    - Khử trùng lặp (deduplicate) trên cả tập Ground Truth và tập Findings trước khi đối sánh,
      đồng thời ghi nhận số bản ghi trùng lặp hoặc không hợp lệ.
    """
    cfg = config or MatchingConfig()

    gt_keys: set[tuple[str, str, str]] = set()
    invalid_gt = 0
    for item in ground_truth:
        try:
            gt_keys.add(extract_matching_key(item, cfg))
        except ValueError:
            invalid_gt += 1

    finding_keys: set[tuple[str, str, str]] = set()
    duplicates_removed = 0
    invalid_findings = 0
    for item in findings:
        try:
            key = extract_matching_key(item, cfg)
        except ValueError:
            invalid_findings += 1
            continue
        if key in finding_keys:
            duplicates_removed += 1
        else:
            finding_keys.add(key)

    tp_keys = sorted(gt_keys & finding_keys)
    fp_keys = sorted(finding_keys - gt_keys)
    fn_keys = sorted(gt_keys - finding_keys)

    tp = len(tp_keys)
    fp = len(fp_keys)
    fn = len(fn_keys)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_score = (
        (2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0.0
        else 0.0
    )

    return {
        "counts": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "ground_truth_total": len(gt_keys),
            "raw_findings_total": len(findings),
            "unique_findings_total": len(finding_keys),
            "duplicates_removed": duplicates_removed,
            "invalid_ground_truth_skipped": invalid_gt,
            "invalid_findings_skipped": invalid_findings,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
        },
        "formulas": {
            "precision": "TP / (TP + FP)",
            "recall": "TP / (TP + FN)",
            "f1_score": "2 * (Precision * Recall) / (Precision + Recall)",
        },
        "matched_tp": [
            {"vuln_category": k[0], "endpoint": k[1], "parameter": k[2]} for k in tp_keys
        ],
        "unmatched_fp": [
            {"vuln_category": k[0], "endpoint": k[1], "parameter": k[2]} for k in fp_keys
        ],
        "missed_fn": [
            {"vuln_category": k[0], "endpoint": k[1], "parameter": k[2]} for k in fn_keys
        ],
    }


def _extract_run_duration(run: dict[str, Any]) -> float | None:
    """Trích xuất thời lượng quét hợp lệ (giây) từ `duration_seconds` hoặc cặp `start_time`/`end_time`."""
    if not isinstance(run, dict):
        return None

    start_raw = run.get("start_time")
    end_raw = run.get("end_time")
    if isinstance(start_raw, str) and isinstance(end_raw, str) and start_raw and end_raw:
        try:
            start_dt = datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end_raw.replace("Z", "+00:00"))
            diff = (end_dt - start_dt).total_seconds()
            if diff >= 0:
                return float(diff)
            return None
        except ValueError:
            pass

    raw_dur = run.get("duration_seconds")
    if isinstance(raw_dur, (int, float)) and not isinstance(raw_dur, bool) and raw_dur >= 0:
        return float(raw_dur)
    return None


def compute_timing_metrics(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Tính thời gian quét trung bình từ danh sách các lần chạy hợp lệ.
    Nếu không có lần chạy nào có thời lượng hợp lệ, trả về trạng thái `measured=False` ("chưa đo").
    """
    valid_durations: list[float] = []
    skipped_runs = 0
    for run in runs:
        dur = _extract_run_duration(run)
        if dur is None:
            skipped_runs += 1
        else:
            valid_durations.append(dur)

    if not valid_durations:
        return {
            "measured": False,
            "status": "chưa đo",
            "valid_runs_count": 0,
            "skipped_runs_count": skipped_runs,
            "average_duration_seconds": None,
            "min_duration_seconds": None,
            "max_duration_seconds": None,
        }

    avg_dur = sum(valid_durations) / len(valid_durations)
    return {
        "measured": True,
        "status": "đã đo",
        "valid_runs_count": len(valid_durations),
        "skipped_runs_count": skipped_runs,
        "average_duration_seconds": round(avg_dur, 2),
        "min_duration_seconds": round(min(valid_durations), 2),
        "max_duration_seconds": round(max(valid_durations), 2),
    }


def compare_tools(
    ground_truth: list[dict[str, Any]],
    scanner_runs: list[dict[str, Any]] | None = None,
    zap_runs: list[dict[str, Any]] | None = None,
    config: MatchingConfig | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Tổng hợp và so sánh kết quả thực nghiệm giữa hệ thống tự phát triển (OWASP Scanner)
    và OWASP ZAP trên cùng tập Ground Truth.
    Không đưa ra kết luận chủ quan nếu một trong hai công cụ chưa có dữ liệu đo thực tế.
    """
    cfg = config or MatchingConfig()
    parsed_scanner = [parse_tool_artifact(r) for r in (scanner_runs or [])]
    parsed_zap = [parse_tool_artifact(r) for r in (zap_runs or [])]

    def evaluate_group(parsed_runs: list[dict[str, Any]]) -> dict[str, Any]:
        if not parsed_runs:
            return {
                "measured": False,
                "status": "chưa đo",
                "classification": None,
                "timing": compute_timing_metrics([]),
            }
        combined_findings: list[dict[str, Any]] = []
        for run in parsed_runs:
            combined_findings.extend(run["findings"])
        return {
            "measured": True,
            "status": "đã đo",
            "classification": compute_classification_metrics(ground_truth, combined_findings, cfg),
            "timing": compute_timing_metrics(parsed_runs),
        }

    return {
        "metadata": metadata or {},
        "matching_config": {
            "match_parameter": cfg.match_parameter,
            "normalize_host": cfg.normalize_host,
            "ignore_param_for_categories": sorted(cfg.ignore_param_for_categories),
        },
        "ground_truth_count": len(ground_truth),
        "scanner": evaluate_group(parsed_scanner),
        "owasp_zap": evaluate_group(parsed_zap),
    }


def render_benchmark_markdown(comparison: dict[str, Any]) -> str:
    """Sinh báo cáo Markdown từ kết quả `compare_tools` (ghi rõ 'chưa đo' nếu thiếu artifact)."""
    meta = comparison.get("metadata", {})
    lines = [
        "# BÁO CÁO ĐỐI CHỨNG THỰC NGHIỆM (BENCHMARK REPORT)",
        "",
        "## 1. Thông tin thực nghiệm (Metadata)",
        f"- **Mục tiêu Lab:** `{meta.get('target', 'chưa đo / chưa cung cấp')}`",
        f"- **Ngày thực hiện:** `{meta.get('date', 'chưa đo')}`",
        f"- **Số lượng lỗ hổng chuẩn (Ground Truth):** `{comparison.get('ground_truth_count', 0)}`",
        "",
        "## 2. Công thức đánh giá",
        "- `Precision = TP / (TP + FP)`",
        "- `Recall = TP / (TP + FN)`",
        "- `F1-Score = 2 * (Precision * Recall) / (Precision + Recall)`",
        "",
        "## 3. Bảng tổng hợp kết quả đối chứng",
        "",
        "| Công cụ | Trạng thái | TP | FP | FN | Precision | Recall | F1-Score | Thời gian TB (s) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for label, key in (("OWASP Web Scanner (Đề tài)", "scanner"), ("OWASP ZAP Baseline", "owasp_zap")):
        entry = comparison.get(key, {})
        if not entry.get("measured") or not entry.get("classification"):
            lines.append(
                f"| {label} | **chưa đo** | - | - | - | - | - | - | chưa đo |"
            )
            continue
        counts = entry["classification"]["counts"]
        metrics = entry["classification"]["metrics"]
        timing = entry.get("timing", {})
        avg_time = (
            f"{timing['average_duration_seconds']}s"
            if timing.get("measured") and timing.get("average_duration_seconds") is not None
            else "chưa đo"
        )
        lines.append(
            f"| {label} | đã đo | {counts['tp']} | {counts['fp']} | {counts['fn']} | "
            f"{metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1_score']:.4f} | {avg_time} |"
        )

    return "\n".join(lines)


def _load_json_list_or_object(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    """CLI tổng hợp chỉ số thực nghiệm từ file Ground Truth và các file artifact JSON."""
    parser = argparse.ArgumentParser(
        prog="benchmark-evaluate",
        description="Tính chỉ số TP, FP, FN, Precision, Recall, F1-Score và thời gian quét từ artifacts.",
    )
    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Đường dẫn tệp JSON chứa danh sách lỗ hổng chuẩn (Ground Truth).",
    )
    parser.add_argument(
        "--scanner-report",
        action="append",
        default=[],
        help="Đường dẫn tệp JSON báo cáo của OWASP Scanner (có thể truyền nhiều lần).",
    )
    parser.add_argument(
        "--zap-report",
        action="append",
        default=[],
        help="Đường dẫn tệp JSON báo cáo của OWASP ZAP (có thể truyền nhiều lần).",
    )
    parser.add_argument(
        "--ignore-param",
        action="store_true",
        help="So khớp chỉ theo loại lỗ hổng và endpoint (bỏ qua tên tham số).",
    )
    parser.add_argument(
        "--target-name",
        default="localhost-lab",
        help="Tên mục tiêu lab để ghi vào metadata báo cáo.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Đường dẫn xuất kết quả tổng hợp (.json hoặc .md).",
    )

    args = parser.parse_args(argv)
    gt_raw = _load_json_list_or_object(Path(args.ground_truth))
    gt_list = gt_raw.get("ground_truth", []) if isinstance(gt_raw, dict) else gt_raw
    if not isinstance(gt_list, list):
        raise ValueError("Tệp ground-truth phải là danh sách JSON hoặc object có khóa 'ground_truth'.")

    scanner_runs = [_load_json_list_or_object(Path(p)) for p in args.scanner_report]
    zap_runs = [_load_json_list_or_object(Path(p)) for p in args.zap_report]

    config = MatchingConfig(match_parameter=not args.ignore_param)
    comparison = compare_tools(
        ground_truth=gt_list,
        scanner_runs=scanner_runs,
        zap_runs=zap_runs,
        config=config,
        metadata={"target": args.target_name},
    )

    markdown = render_benchmark_markdown(comparison)
    print(markdown)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.suffix.lower() == ".json":
            out_path.write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            out_path.write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
