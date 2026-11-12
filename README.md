# DACN

<<<<<<< Updated upstream
## Web Backend API (Module 5)

Install dependencies with `pip install -r requirements.txt`, then start the
development API with `python app.py`. The API listens on `http://127.0.0.1:5000`.
Register via `POST /api/auth/register`, log in via `POST /api/auth/login`, and
send the returned JWT as `Authorization: Bearer <token>` to `/api/scans`.
=======
Hệ thống rà quét lỗ hổng bảo mật ứng dụng Web tự động theo chuẩn **OWASP Top 10** (`SQL Injection`, `Cross-Site Scripting - XSS`, `Cross-Site Request Forgery - CSRF`, `Security Misconfiguration / Missing Security Headers`), hỗ trợ giao diện dòng lệnh (CLI), RESTful API, Web Dashboard trực quan, xuất báo cáo kỹ thuật (`TXT`/`PDF`) và bộ công cụ đánh giá thực nghiệm (Benchmark) trong môi trường Docker cô lập.

> **Cảnh báo an toàn & Đạo đức (Authorized Local Lab Only):**
> Công cụ này chỉ phục vụ mục đích học tập, nghiên cứu và kiểm thử trên môi trường Lab cục bộ được cấp phép (`localhost`, `*.localhost`, hoặc địa chỉ IP loopback `127.0.0.0/8` / `::1`). Mọi mục tiêu bên ngoài loopback, địa chỉ IP LAN/private, link-local/cloud metadata (`169.254.169.254`), hostname phân giải ra IP ngoài loopback hoặc HTTP redirect sang host ngoài loopback đều bị chặn cứng ở cả API, CLI, Engine, Crawler và `SafeHTTPClient`.
>>>>>>> Stashed changes

Scan jobs run on a background thread. For lab safety, the scan API only accepts
HTTP(S) targets on `localhost`, `*.localhost`, or a loopback IP address. Run
tests with `pytest tests/test_module5.py`.

<<<<<<< Updated upstream
## Cấu hình triển khai & Giới hạn kiến trúc (Module 5)
=======
## 1. Cài đặt & Cấu hình an toàn

### 1.1. Yêu cầu hệ thống
- **Python**: `>= 3.10` (khuyến nghị Python 3.11–3.14)
- **Docker & Docker Compose**: Tuỳ chọn, chỉ cần khi khởi chạy môi trường Lab Benchmark cục bộ (`DVWA`, `OWASP Juice Shop`, `OWASP ZAP`).

### 1.2. Cài đặt thư viện
```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### 1.3. Cấu hình biến môi trường (`.env`)
Sao chép từ `.env.example` sang `.env` tại thư mục gốc dự án (tuyệt đối không commit khóa bí mật thật lên Git):

```ini
APP_ENV=development
FLASK_DEBUG=0
DATABASE_URL=sqlite:///instance/scanner.db

# Khóa bí mật (Bắt buộc >= 32 ký tự ngẫu nhiên khi APP_ENV=production)
SECRET_KEY=CHANGE_ME_EXAMPLE_FLASK_SECRET_KEY_MIN_32_CHARS
JWT_SECRET_KEY=CHANGE_ME_EXAMPLE_JWT_SECRET_KEY_MIN_32_CHARS

# Khóa mã hóa AES-GCM cho dữ liệu nhạy cảm trong DB (32 bytes ở dạng hex 64 ký tự hoặc base64)
# Sinh khóa mới: python -c "import secrets; print(secrets.token_hex(32))"
ENCRYPTION_MASTER_KEY=CHANGE_ME_EXAMPLE_64_HEX_CHARS_DO_NOT_USE_IN_PRODUCTION_00000000

# Cấu hình Reverse Proxy & Worker (Single-process)
TRUSTED_PROXIES=
WORKER_PROCESSES=1

# Tùy chọn đường dẫn tới font TrueType (.ttf) hỗ trợ Unicode tiếng Việt khi xuất PDF
REPORT_UNICODE_FONT_PATH=
```

---

## 2. Danh mục Module Rà quét & Giới hạn An toàn

### 2.1. Các module đang hỗ trợ (`ALL_MODULES`)
Hệ thống đồng bộ danh sách **4 module rà quét hoạt động** xuyên suốt giữa `SCANNER_REGISTRY`, REST API (`POST /api/scans`), giao diện Web Dashboard và CLI (`scanner.py`):

| Mã module | Lớp thực thi | Mô tả & CWE tương ứng |
|---|---|---|
| `sqli` | `SQLiScanner` | Phát hiện SQL Injection dựa trên thông báo lỗi DBMS (Error-based) và sai khác phản hồi Boolean-based (`CWE-89`). Không dùng payload time-delay hoặc phá hoại dữ liệu. |
| `xss` | `XSSScanner` | Phát hiện Reflected XSS và phản chiếu đầu vào chưa mã hóa theo ngữ cảnh HTML/Attribute (`CWE-79`). |
| `csrf` | `CSRFScanner` | Phát hiện biểu mẫu thay đổi trạng thái (`POST`/`PUT`/`DELETE`/`PATCH`) thiếu CSRF token và kiểm tra thuộc tính `SameSite` của cookie phiên (`CWE-352`). |
| `headers` | `HeaderScanner` | Kiểm tra thiếu hoặc cấu hình yếu các HTTP Security Headers (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) (`CWE-16`, `CWE-693`, `CWE-1021`). |

### 2.2. Các module bị vô hiệu hóa / không hỗ trợ trong phạm vi Lab an toàn
- **`ssrf` (`SSRFScanner` — Disabled/Unsupported)**: Phát hiện Blind/Out-of-Band SSRF đòi hỏi dịch vụ callback bên ngoài (Interactsh/webhook) hoặc gửi request thăm dò địa chỉ nội bộ/metadata. Theo giới hạn an toàn bắt buộc của dự án (chỉ kết nối loopback cục bộ, không gọi dịch vụ ngoài), module `ssrf` bị vô hiệu hóa chủ động (`SSRFScannerUnsupportedError`) và không thực hiện bất kỳ kết nối mạng nào.
- **Các tên danh mục cũ không triển khai (`auth`, `access_control`, `misconfig`)**: Không nằm trong `ALL_MODULES`; nếu gửi qua API hoặc CLI sẽ bị từ chối với thông báo rõ danh sách module hợp lệ (`csrf, headers, sqli, xss`).

---

## 3. Khởi chạy Web Backend API & Web Dashboard (Module 5 & Module 6.1)

Khởi động máy chủ Flask:
```bash
python app.py
```
Máy chủ lắng nghe mặc định tại `http://127.0.0.1:5000`.

### Các trang giao diện Web Dashboard (Module 6.1)
- **`GET /` hoặc `GET /dashboard`**: Trang tổng quan phiên quét:
  - Đăng nhập / Đăng ký tài khoản trực tiếp trên giao diện (lưu JWT trong `sessionStorage`, không đưa token lên URL hay `console.log`).
  - Thống kê tổng số phiên quét, số phiên đang hoạt động, số lỗ hổng nghiêm trọng (`CRITICAL` + `HIGH`).
  - Biểu đồ phân bố mức độ nghiêm trọng (`Severity Distribution`) hiển thị qua Chart.js (kèm cơ chế vẽ Canvas 2D dự phòng khi chạy offline).
  - Tạo phiên quét mới với Target URL (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`), chọn các module hỗ trợ (`sqli`, `xss`, `csrf`, `headers`) và độ sâu thu thập (`max_depth` từ `1` đến `5`).
- **`GET /scans/<id>`**: Trang chi tiết phiên quét:
  - Tự động cập nhật (polling) trạng thái và tiến độ (`0% - 100%`), tự động dừng polling khi phiên chuyển sang trạng thái kết thúc (`COMPLETED`, `FAILED`, `CANCELLED`, `NO_MODULES`).
  - Cho phép chủ sở hữu dừng phiên quét đang chạy (`POST /api/scans/<id>/stop`).
  - Bộ lọc lỗ hổng phía client theo mức độ nghiêm trọng (`findingSeverityFilter`) và từ khóa tìm kiếm (`findingKeywordFilter` trên loại lỗ hổng, URL, tham số, CWE/OWASP) cùng nút xóa bộ lọc (`clearFindingFilterBtn`); cửa sổ Modal xem chi tiết kỹ thuật (`URL`, `Parameter`, `Payload`, `Evidence`, `CWE/OWASP`, `Remediation`) được render hoàn toàn bằng DOM API và `textContent` để chống XSS.

### Các Endpoint REST API chính
- `POST /api/auth/register` — Đăng ký tài khoản mới.
- `POST /api/auth/login` — Đăng nhập và nhận `access_token` (JWT).
- `GET /api/scans` — Danh sách phiên quét của người dùng hiện tại (`Authorization: Bearer <token>`).
- `POST /api/scans` — Khởi tạo phiên quét mới (`url`, `modules`, `max_depth`).
- `GET /api/scans/<id>` — Xem trạng thái và tiến độ phiên quét.
- `GET /api/scans/<id>/findings` — Danh sách lỗ hổng phát hiện được.
- `POST /api/scans/<id>/stop` — Yêu cầu hủy phiên quét đang ở trạng thái `PENDING`, `RUNNING`, `CRAWLING`, hoặc `SCANNING`.
- `GET /api/scans/<id>/report?format=pdf|txt` — Tải báo cáo kỹ thuật của phiên quét.

---

## 4. Xuất & Tải báo cáo kỹ thuật TXT/PDF (Module 6.2)

### 4.1. Qua REST API / Web Dashboard
- Trên giao diện `/dashboard` hoặc `/scans/<id>`, nhấn nút **TXT** hoặc **PDF** để tải báo cáo về máy.
- Hoặc gọi trực tiếp qua API với JWT của chủ sở hữu phiên quét:
  ```bash
  curl -H "Authorization: Bearer <JWT_TOKEN>" \
       "http://127.0.0.1:5000/api/scans/1/report?format=txt" -o scan_1_report.txt

  curl -H "Authorization: Bearer <JWT_TOKEN>" \
       "http://127.0.0.1:5000/api/scans/1/report?format=pdf" -o scan_1_report.pdf
  ```
- **Quy tắc bảo mật & kết xuất báo cáo**:
  - Yêu cầu xác thực JWT (`401` nếu thiếu/hết hạn).
  - Kiểm tra quyền sở hữu phiên quét: trả `404` nếu phiên không tồn tại hoặc thuộc người dùng khác.
  - Chỉ chấp nhận định dạng chính xác `format=pdf` hoặc `format=txt` (`400` cho mọi giá trị khác).
  - Tự động tính toán lại thống kê mức độ nghiêm trọng (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) trực tiếp từ danh sách findings thực tế để đồng bộ giữa báo cáo TXT và PDF.
  - Hỗ trợ nhúng font TrueType Unicode tiếng Việt qua biến môi trường `REPORT_UNICODE_FONT_PATH` hoặc tự động dò tìm font hệ thống (`Arial`, `Tahoma`, `Segoe UI`, `DejaVuSans`, `LiberationSans`, `NotoSans`). Nếu môi trường tối giản không có bất kỳ font `.ttf` nào, hệ thống ghi chú rõ chế độ fallback `Helvetica (ASCII transliteration fallback)` và chuyển đổi dấu tiếng Việt sang ASCII rõ nghĩa thay vì hiển thị ký tự lỗi.
  - Làm sạch ký tự điều khiển XML không hợp lệ và escape đầy đủ `<`, `>`, `&`, `'`, `"` trước khi đưa vào `Paragraph` của ReportLab.

### 4.2. Qua CLI (`scanner.py`)
Công cụ CLI dùng chung chính sách kiểm tra mục tiêu loopback (`validate_target_url`) và danh sách module (`sqli,xss,csrf,headers`) với REST API:
```bash
python scanner.py -u http://127.0.0.1:4280 -m sqli,xss,csrf,headers -d 2 -t 5 -o reports/txt/report.txt
```
Xem hướng dẫn đầy đủ các tham số dòng lệnh:
```bash
python scanner.py --help
```

---

## 5. Benchmark & Đánh giá thực nghiệm (Module 7)

Toàn bộ cấu hình Docker Lab, định dạng dữ liệu Ground Truth, dữ liệu mẫu (`benchmark/fixtures/`) và công cụ tính toán chỉ số đánh giá nằm trong thư mục [`benchmark/`](benchmark/README.md).

### 5.1. Khởi chạy Lab Docker cục bộ (Chỉ bind `127.0.0.1`)
```bash
docker compose -f benchmark/docker-compose.yml up -d
```
- **DVWA**: `http://127.0.0.1:4280`
- **OWASP Juice Shop**: `http://127.0.0.1:3000`

### 5.2. Chạy công cụ tính chỉ số Precision, Recall, F1-Score & Thời gian quét
Công cụ `benchmark/evaluate.py` đối sánh danh sách lỗ hổng phát hiện từ báo cáo JSON của Scanner (`--scanner-report`) và báo cáo JSON của OWASP ZAP (`--zap-report`) với bộ dữ liệu chuẩn (`--ground-truth`) theo bộ khóa chuẩn hóa `(vuln_category, endpoint, parameter)`.

Chạy thử nghiệm ngay với bộ dữ liệu mẫu có sẵn trong `benchmark/fixtures/`:
```bash
python -m benchmark.evaluate \
  --ground-truth benchmark/fixtures/ground_truth_sample.json \
  --scanner-report benchmark/fixtures/scanner_sample.json \
  --zap-report benchmark/fixtures/zap_sample.json \
  --target-name "Sample Fixture Demo (Synthetic)" \
  -o benchmark/artifacts/fixture_summary.md
```
Các tham số hỗ trợ của `python -m benchmark.evaluate`:
- `--ground-truth` (bắt buộc): Đường dẫn tới file JSON Ground Truth.
- `--scanner-report` (tùy chọn, có thể lặp lại hoặc truyền danh sách phân tách dấu phẩy): Đường dẫn tới báo cáo JSON của OWASP Web Scanner. Nếu không truyền, báo cáo ghi rõ trạng thái **`chưa đo`**.
- `--zap-report` (tùy chọn, có thể lặp lại hoặc truyền danh sách phân tách dấu phẩy): Đường dẫn tới báo cáo JSON của OWASP ZAP Baseline. Nếu không truyền, báo cáo ghi rõ trạng thái **`chưa đo`**.
- `--ignore-param` (tùy chọn): Đối sánh theo `(vuln_category, endpoint)` không xét tên tham số.
- `--target-name` (tùy chọn): Tên mục tiêu hiển thị trên báo cáo Markdown.
- `-o`, `--output` (tùy chọn): Đường dẫn file Markdown đầu ra (nếu lược bỏ sẽ in ra `stdout`).

Xem hướng dẫn chi tiết, quy tắc chuẩn hóa CWE chính xác (`CWE-<number>`) và phân loại `TP`/`FP`/`FN` tại [`benchmark/README.md`](benchmark/README.md).

---

## 6. Chạy kiểm thử tự động (Unit & Integration Tests)

Chạy các bài kiểm thử của Module 5, Module 6, Module 7 và SQLiScanner:
```bash
pytest tests/test_module5.py tests/test_sqli.py tests/test_module6_7.py -v
```

Hoặc chạy toàn bộ test suite trong repository (bao gồm bộ kiểm thử bảo mật `tests/security/` và worker `tests/worker/`):
```bash
pytest -v
```

---

## 7. Cấu hình triển khai & Giới hạn kiến trúc
>>>>>>> Stashed changes

### 1. Chính sách mục tiêu Loopback-Only thống nhất (`core/security/`)
- Mọi URL đầu vào qua API (`schemas/requested_scope_schema.py`), CLI (`scanner.py`), Engine (`core/engine/scan_engine.py`), Crawler (`core/crawler/bfs_crawler.py`), Scanner (`core/scanners/base_scanner.py`) và HTTP Client (`core/utils/safe_http_client.py`) đều được kiểm tra qua `validate_target_url`:
  - Chỉ cho phép scheme `http` hoặc `https`.
  - Không cho phép thông tin xác thực nhúng trong URL (`user:pass@host`).
  - Hostname chỉ được phép là `localhost`, `*.localhost`, hoặc địa chỉ IP loopback `127.0.0.0/8` và `::1`.
  - Phân giải DNS (`core/security/dns_resolver.py`) và xác minh mọi IP trả về đều là loopback để chống tấn công DNS Rebinding.
  - Kiểm tra thủ công từng bước HTTP Redirect (`301`, `302`, `303`, `307`, `308`, tối đa 3 bước) và chặn ngay nếu `Location` trỏ ra ngoài loopback.

### 2. Môi trường Production & Biến môi trường bảo mật
- Khi `APP_ENV=production`, ứng dụng bắt buộc cấu hình `SECRET_KEY` và `JWT_SECRET_KEY` có độ dài tối thiểu **32 ký tự** và không trùng giá trị mặc định của môi trường development. Nếu thiếu hoặc yếu, `create_app()` sẽ ném `RuntimeError` và dừng khởi động.

### 3. Rate Limiter & Reverse Proxy (`TRUSTED_PROXIES`)
- Mặc định `TRUSTED_PROXIES` để trống: rate limiter luôn dùng `request.remote_addr` và **bỏ qua** `X-Forwarded-For` để ngăn client trực tiếp giả mạo IP.
- Chỉ khi triển khai phía sau reverse proxy tin cậy mới cấu hình danh sách IP hoặc CIDR của proxy qua biến môi trường `TRUSTED_PROXIES` (ví dụ: `TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8`).

### 4. Kiến trúc Hàng đợi Nền Single-Process (`WORKER_PROCESSES=1`)
- Dự án sử dụng kiến trúc hàng đợi nền trong bộ nhớ (`queue.Queue` + daemon worker thread trong `services/scan_service.py`) kết hợp cơ chế khôi phục phiên quét từ SQLite (`recover_pending_scans`) và `threading.Event` riêng cho từng phiên quét để xử lý tín hiệu dừng (`POST /api/scans/<id>/stop`).
- Hệ thống được thiết kế cho mô hình **1 process + nhiều luồng** (`WORKER_PROCESSES=1`). Các file `config/celery_config.py` và `tasks/celery_app.py` chỉ đóng vai trò giữ chỗ kiến trúc (`CELERY_ENABLED = False`) và không kích hoạt hệ thống hàng đợi thứ hai.
