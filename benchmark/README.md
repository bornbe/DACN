# Hướng dẫn Benchmark Thực nghiệm & Đối chứng OWASP ZAP (Module 7)

> **CẢNH BÁO AN TOÀN & PHẠM VI KIỂM THỬ:**
> Toàn bộ quy trình benchmark này **chỉ được phép chạy trên môi trường lab cục bộ cô lập** (`127.0.0.1` / `localhost` / `.localhost` / `::1`) với các ứng dụng mẫu có chủ đích chứa lỗ hổng (**DVWA**, **OWASP Juice Shop**). Tuyệt đối không sử dụng để quét bất kỳ hệ thống bên ngoài nào.

---

## 1. Khởi tạo Môi trường Lab Docker Cục bộ (Issue #7.1)

File [`benchmark/docker-compose.yml`](./docker-compose.yml) định nghĩa 2 mục tiêu chuẩn hóa và chỉ bind cổng vào `127.0.0.1`:
- **DVWA:** `http://127.0.0.1:4280`
- **OWASP Juice Shop:** `http://127.0.0.1:3000`

Khởi chạy thủ công khi cần thực nghiệm:
```bash
docker compose -f benchmark/docker-compose.yml up -d
```

Dừng và dọn dẹp sau khi hoàn tất thực nghiệm:
```bash
docker compose -f benchmark/docker-compose.yml down -v
```

---

## 2. Kiểm tra Nhanh Công cụ Đánh giá bằng Fixture Mẫu Có Sẵn (Offline)

Repository cung cấp sẵn bộ tệp fixture mẫu giả lập (`is_synthetic_fixture: true`) trong thư mục `benchmark/fixtures/` để kiểm chứng công cụ `benchmark/evaluate.py` mà không cần bật Docker:

```bash
python -m benchmark.evaluate \
  --ground-truth benchmark/fixtures/ground_truth_sample.json \
  --scanner-report benchmark/fixtures/scanner_sample.json \
  --zap-report benchmark/fixtures/zap_sample.json \
  --target-name "Local Fixture Verification (127.0.0.1:3000)" \
  -o benchmark/artifacts/fixture_summary.md
```

Hoặc xuất kết quả dạng JSON:
```bash
python -m benchmark.evaluate \
  --ground-truth benchmark/fixtures/ground_truth_sample.json \
  --scanner-report benchmark/fixtures/scanner_sample.json \
  --zap-report benchmark/fixtures/zap_sample.json \
  -o benchmark/artifacts/fixture_summary.json
```

> **Lưu ý:** Nếu chỉ truyền `--scanner-report` mà không truyền `--zap-report` (hoặc ngược lại, hoặc không truyền cả hai), công cụ sẽ tự động ghi nhận **`chưa đo`** cho phía thiếu dữ liệu và tuyệt đối không bịa số liệu.

---

## 3. Thu thập Raw Artifacts Thực nghiệm từ OWASP Scanner & OWASP ZAP

### 3.1. Chạy quét bằng OWASP Scanner của đề tài
```bash
python scanner.py -u http://127.0.0.1:3000 -d 2 -m all -o benchmark/artifacts/scanner_juiceshop_run1.json --no-db
```

### 3.2. Chạy quét đối chứng bằng OWASP ZAP Baseline (Docker cục bộ)
```bash
docker run --rm --network host -v "$(pwd)/benchmark/artifacts:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://127.0.0.1:3000 \
  -J zap_juiceshop_run1.json
```

### 3.3. Tổng hợp kết quả sau khi đã sinh Artifacts thực tế
```bash
python -m benchmark.evaluate \
  --ground-truth benchmark/fixtures/ground_truth_sample.json \
  --scanner-report benchmark/artifacts/scanner_juiceshop_run1.json \
  --zap-report benchmark/artifacts/zap_juiceshop_run1.json \
  --target-name "OWASP Juice Shop (127.0.0.1:3000)" \
  -o benchmark/artifacts/live_summary.md
```

---

## 4. Định dạng Dữ liệu Đầu vào & Quy tắc Matching (Issue #7.2)

### 4.1. Định dạng tệp Ground Truth (`benchmark/fixtures/ground_truth_sample.json`)
```json
{
  "metadata": {
    "target": "http://127.0.0.1:3000",
    "description": "Danh sách lỗ hổng chuẩn hóa dùng để đối sánh"
  },
  "ground_truth": [
    {
      "vuln_category": "sqli",
      "target_url": "http://127.0.0.1:3000/rest/products/search",
      "parameter": "q",
      "cwe_id": "CWE-89"
    },
    {
      "vuln_category": "xss",
      "target_url": "http://127.0.0.1:3000/search",
      "parameter": "q",
      "cwe_id": "CWE-79"
    },
    {
      "vuln_category": "csrf",
      "target_url": "http://127.0.0.1:3000/profile",
      "parameter": "username",
      "cwe_id": "CWE-352"
    },
    {
      "vuln_category": "headers",
      "target_url": "http://127.0.0.1:3000/",
      "parameter": "",
      "cwe_id": "CWE-693"
    }
  ]
}
```

### 4.2. Quy tắc Matching, Chuẩn hóa CWE & Khử trùng lặp (Deduplication)
Công cụ [`benchmark/evaluate.py`](./evaluate.py) chuẩn hóa mỗi phát hiện thành bộ khóa `(vuln_category, endpoint_path, parameter)`:
1. **`vuln_category`**:
   - Chuẩn hóa mã CWE (`89`, `"89"`, `"089"`, `"CWE-89"`) về dạng chuẩn `CWE-<số>` rồi **so khớp chính xác** với bảng CWE được hỗ trợ (`CWE-89` -> `sqli`, `CWE-79` -> `xss`, `CWE-352` -> `csrf`, `CWE-693`/`CWE-1021`/`CWE-16` -> `headers`). Không dùng phép tìm chuỗi con để tránh nhận nhầm `CWE-189` thành `CWE-89`.
   - Với CWE hoặc loại lỗ hổng không nằm trong danh sách hỗ trợ, giữ nguyên định danh chuẩn hóa (ví dụ `cwe-189` hoặc tên loại lỗ hổng) chứ không gán ép sang nhóm sai.
2. **`endpoint_path`**: chuẩn hóa đường dẫn URL (bỏ query string và fragment, chuẩn hóa dấu `/` cuối).
3. **`parameter`**: tên tham số viết thường (đối với nhóm `headers` cấp site hoặc khi bật cờ `--ignore-param`, tham số được chuẩn hóa thành `""`).
4. **Khử trùng lặp (`deduplication`)**: nếu một công cụ báo cáo nhiều phát hiện trùng cùng một bộ khóa `(vuln_category, endpoint_path, parameter)`, bộ đánh giá chỉ tính 1 lần vào tập kết quả duy nhất và ghi nhận số lượng bản ghi trùng tại trường `duplicates_removed`.

### 4.3. Công thức tính toán chỉ số khoa học
- $\text{Precision} = \frac{TP}{TP + FP}$ (bằng `0.0` nếu $TP + FP = 0$)
- $\text{Recall} = \frac{TP}{TP + FN}$ (bằng `0.0` nếu $TP + FN = 0$)
- $F_1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$ (bằng `0.0` nếu $\text{Precision} + \text{Recall} = 0$)

---

## 5. Trạng thái Số liệu Thực nghiệm Live Hiện tại

> **Lưu ý trung thực học thuật:** Trong môi trường kiểm thử tự động hiện tại chưa khởi chạy container Docker DVWA / OWASP Juice Shop và OWASP ZAP, do đó bảng đối chứng thực tế dưới đây được ghi nhận đúng trạng thái **chưa đo**.

| Công cụ | Trạng thái | TP | FP | FN | Precision | Recall | F1-Score | Thời gian TB (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| OWASP Web Scanner (Đề tài) | **chưa đo** | - | - | - | - | - | - | chưa đo |
| OWASP ZAP Baseline | **chưa đo** | - | - | - | - | - | - | chưa đo |
