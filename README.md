# DACN

## Web Backend API (Module 5)

Install dependencies with `pip install -r requirements.txt`, then start the
development API with `python app.py`. The API listens on `http://127.0.0.1:5000`.
Register via `POST /api/auth/register`, log in via `POST /api/auth/login`, and
send the returned JWT as `Authorization: Bearer <token>` to `/api/scans`.

Scan jobs run on a background thread. For lab safety, the scan API only accepts
HTTP(S) targets on `localhost`, `*.localhost`, or a loopback IP address. Run
tests with `pytest tests/test_module5.py`.

## Cấu hình triển khai & Giới hạn kiến trúc (Module 5)

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
