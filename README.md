# DACN — OWASP Web Vulnerability Scanner

Hệ thống rà quét lỗ hổng bảo mật ứng dụng Web tự động theo chuẩn **OWASP Top 10:2025** (`A01` Broken Access Control, `A02` Security Misconfiguration, `A05` Injection: SQLi & XSS, `A07` Authentication Failures), hỗ trợ giao diện dòng lệnh (CLI), RESTful API, Web Dashboard trực quan, xuất báo cáo kỹ thuật (`TXT`/`PDF`) và bộ công cụ đánh giá thực nghiệm (Benchmark) trong môi trường Docker cô lập.

> **Cảnh báo an toàn & Đạo đức (Authorized Local Lab Only):**
> Công cụ này chỉ phục vụ mục đích học tập, nghiên cứu và kiểm thử trên môi trường Lab cục bộ được cấp phép (`localhost`, `*.localhost`, hoặc địa chỉ IP loopback `127.0.0.1` / `::1`). Tuyệt đối không sử dụng để rà quét các hệ thống trên Internet hoặc mục tiêu không thuộc quyền sở hữu.

---

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
Tạo file `.env` tại thư mục gốc dự án (tuyệt đối không commit khóa bí mật thật lên Git):

```ini
APP_ENV=development
FLASK_DEBUG=0
DATABASE_URL=sqlite:///instance/scanner.db

# Khóa bí mật (Bắt buộc >= 32 ký tự ngẫu nhiên khi APP_ENV=production)
SECRET_KEY=replace-with-at-least-32-bytes-random-secret-key
JWT_SECRET_KEY=replace-with-at-least-32-bytes-random-jwt-secret

# Khóa mã hóa AES-GCM cho dữ liệu nhạy cảm trong DB (32 bytes ở dạng hex 64 ký tự hoặc base64)
# Sinh khóa mới: python -c "import secrets; print(secrets.token_hex(32))"
ENCRYPTION_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Cấu hình Reverse Proxy & Worker
TRUSTED_PROXIES=
WORKER_PROCESSES=1
```

---

## 2. Khởi chạy Web Backend API & Web Dashboard (Module 5 & Module 6.1)

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
  - Tạo phiên quét mới với Target URL (`localhost`/`127.0.0.1`), chọn các module (`sqli`, `xss`, `auth`, `misconfig`, `access_control`) và độ sâu thu thập (`max_depth` từ `1` đến `5`).
- **`GET /scans/<id>`**: Trang chi tiết phiên quét:
  - Tự động cập nhật (polling) trạng thái và tiến độ (`0% - 100%`), tự động dừng polling khi phiên chuyển sang trạng thái kết thúc (`COMPLETED`, `FAILED`, `CANCELLED`, `NO_MODULES`).
  - Cho phép chủ sở hữu dừng phiên quét đang chạy (`POST /api/scans/<id>/stop`).
  - Bộ lọc lỗ hổng theo mức độ nghiêm trọng và từ khóa; cửa sổ Modal xem chi tiết kỹ thuật (`URL`, `Parameter`, `Payload`, `Evidence`, `CWE/OWASP`, `Remediation`) được render an toàn chống XSS.

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

## 3. Xuất & Tải báo cáo kỹ thuật TXT/PDF (Module 6.2)

### 3.1. Qua REST API / Web Dashboard
- Trên giao diện `/dashboard` hoặc `/scans/<id>`, nhấn nút **TXT** hoặc **PDF** để tải báo cáo về máy.
- Hoặc gọi trực tiếp qua API với JWT của chủ sở hữu phiên quét:
  ```bash
  curl -H "Authorization: Bearer <JWT_TOKEN>" \
       "http://127.0.0.1:5000/api/scans/1/report?format=txt" -o scan_1_report.txt

  curl -H "Authorization: Bearer <JWT_TOKEN>" \
       "http://127.0.0.1:5000/api/scans/1/report?format=pdf" -o scan_1_report.pdf
  ```
- **Quy tắc bảo mật endpoint báo cáo**:
  - Yêu cầu xác thực JWT (`401` nếu thiếu/hết hạn).
  - Kiểm tra quyền sở hữu phiên quét: trả `404` nếu phiên không tồn tại hoặc thuộc người dùng khác.
  - Chỉ chấp nhận định dạng chính xác `format=pdf` hoặc `format=txt` (`400` cho mọi giá trị khác).
  - Tự động làm sạch/escape các ký tự HTML/XML đặc biệt (`<`, `>`, `&`, ký tự điều khiển) trong dữ liệu finding trước khi kết xuất PDF bằng ReportLab.

### 3.2. Qua CLI (`scanner.py`)
```bash
python scanner.py --url http://127.0.0.1:4280 --modules sqli,xss,misconfig --depth 2 --format txt --output report.txt
```

---

## 4. Benchmark & Đánh giá thực nghiệm (Module 7)

Toàn bộ cấu hình Docker Lab, định dạng dữ liệu Ground Truth và công cụ tính toán chỉ số đánh giá nằm trong thư mục [`benchmark/`](benchmark/README.md).

### 4.1. Khởi chạy Lab Docker cục bộ (Chỉ bind `127.0.0.1`)
```bash
docker compose -f benchmark/docker-compose.yml up -d
```
- **DVWA**: `http://127.0.0.1:4280`
- **OWASP Juice Shop**: `http://127.0.0.1:3000`

### 4.2. Chạy công cụ tính chỉ số Precision, Recall, F1-Score & Thời gian quét
Công cụ `benchmark/evaluate.py` đối sánh danh sách lỗ hổng phát hiện từ báo cáo JSON của Scanner và báo cáo JSON của OWASP ZAP với bộ dữ liệu chuẩn (`ground_truth.json`) theo bộ khóa chuẩn hóa `(vuln_category, endpoint, parameter)`:

```bash
python -m benchmark.evaluate \
  --ground-truth benchmark/data/ground_truth_sample.json \
  --scanner-reports benchmark/data/scanner_run1.json \
  --zap-reports benchmark/data/zap_baseline.json \
  --output-md benchmark/results_summary.md \
  --output-json benchmark/results_summary.json
```
Xem hướng dẫn chi tiết, quy tắc phân loại `TP`/`FP`/`FN` và mẫu báo cáo đối sánh tại [`benchmark/README.md`](benchmark/README.md).

---

## 5. Chạy kiểm thử tự động (Unit & Integration Tests)

Chạy toàn bộ các bài kiểm thử của Module 5, Module 6, Module 7 và SQLiScanner:
```bash
pytest tests/test_module5.py tests/test_sqli.py tests/test_module6_7.py -v
```

Hoặc chạy toàn bộ test suite trong repository:
```bash
pytest -v
```

---

## 6. Cấu hình triển khai & Giới hạn kiến trúc (Module 5)

### 1. Môi trường Production & Biến môi trường bảo mật
- Khi `APP_ENV=production`, ứng dụng bắt buộc cấu hình `SECRET_KEY` và `JWT_SECRET_KEY` có độ dài tối thiểu **32 ký tự** và không trùng giá trị mặc định của môi trường development. Nếu thiếu hoặc yếu, `create_app()` sẽ ném `RuntimeError` và dừng khởi động.

### 2. Rate Limiter & Reverse Proxy (`TRUSTED_PROXIES`)
- Mặc định `TRUSTED_PROXIES` để trống: rate limiter luôn dùng `request.remote_addr` và **bỏ qua** `X-Forwarded-For` để ngăn client trực tiếp giả mạo IP.
- Chỉ khi triển khai phía sau reverse proxy tin cậy (Nginx/HAProxy/Cloudflare đã ghi đè `X-Forwarded-For`), mới cấu hình danh sách IP hoặc CIDR của proxy qua biến môi trường `TRUSTED_PROXIES` (ví dụ: `TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8`).
- Rate limiter chỉ trích xuất client IP từ `X-Forwarded-For` khi `request.remote_addr` nằm trong allowlist `TRUSTED_PROXIES`. Cấu hình `TRUSTED_PROXY=true` đơn lẻ mà không có `TRUSTED_PROXIES` sẽ không được tin cậy.

### 3. Giới hạn Single-Process (`WORKER_PROCESSES=1`)
- Bộ đếm rate limit, hàng đợi tác vụ quét (`queue.Queue` + daemon worker thread) và registry tín hiệu hủy (`threading.Event` cho `POST /api/scans/<id>/stop`) được lưu trong RAM của một process duy nhất.
- Hệ thống được thiết kế cho mô hình **1 process + nhiều luồng** (ví dụ: `python app.py` hoặc `gunicorn --workers 1 --threads 8 "app:create_app()"`).
- Cấu hình `WORKER_PROCESSES` / `WEB_CONCURRENCY` khác `1` sẽ bị từ chối khi khởi động để tránh nhân bội quota rate limit per-IP, mất tín hiệu hủy scan giữa các process và chạy trùng phiên quét khi recovery.

### 4. Khôi phục phiên quét khi khởi động (`recover_pending_scans`)
- Khi khởi động (ngoài chế độ `TESTING`), hệ thống tự động tìm các phiên đang dang dở (`PENDING`, `RUNNING`, `CRAWLING`, `SCANNING`), đưa các phiên đang chạy dở về `PENDING` (`progress = 0`) trong một transaction nguyên tử và đưa lại vào hàng đợi nền.
- Các phiên đã kết thúc (`COMPLETED`, `CANCELLED`, `FAILED`, `NO_MODULES`) không bao giờ bị khôi phục lại, và cơ chế deduplication ngăn cùng một phiên bị enqueue hoặc thực thi hai lần trong cùng process.
