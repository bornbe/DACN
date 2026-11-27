# Hướng dẫn Triển khai Nền tảng lên `okiaconpet.cloud` qua Cloudflare Tunnel

Tài liệu này hướng dẫn cấu hình và vận hành hệ thống **OWASP Web Vulnerability Scanner** trên tên miền `https://okiaconpet.cloud` bằng **Docker Compose** và **Cloudflare Zero Trust Tunnel (`cloudflared`)**.

---

## 1. Sinh khóa bảo mật cho Production (`.env`)

Tạo tệp `.env` tại thư mục gốc `scannerweb` và sinh các khóa ngẫu nhiên đủ độ mạnh (`>= 32` ký tự):

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48))"
python -c "import os, base64; print('ENCRYPTION_MASTER_KEY=' + base64.b64encode(os.urandom(32)).decode())"
```

Ví dụ nội dung `.env` cho Production:

```ini
APP_ENV=production
APP_BASE_URL=https://okiaconpet.cloud
TARGET_VERIFICATION_REQUIRED=true
AUTHORIZED_TARGET_DOMAINS=okiaconpet.cloud

SECRET_KEY=<chuoi_ngau_nhien_48_bytes>
JWT_SECRET_KEY=<chuoi_ngau_nhien_48_bytes>
ENCRYPTION_MASTER_KEY=<chuoi_base64_32_bytes>

POSTGRES_DB=scannerweb
POSTGRES_USER=scanner
POSTGRES_PASSWORD=<mat_khau_postgres_manh>

WORKER_PROCESSES=1
TRUSTED_PROXIES=172.28.0.0/16,127.0.0.1/32
CLOUDFLARE_TUNNEL_TOKEN=<token_tu_cloudflare_zero_trust>
```

---

## 2. Cấu hình Cloudflare Zero Trust Tunnel

1. Đăng nhập **Cloudflare Zero Trust Dashboard** -> **Networks** -> **Tunnels**.
2. Chọn **Create a tunnel** -> chọn loại **Cloudflared** -> đặt tên `okiaconpet-scanner`.
3. Sao chép giá trị **Tunnel Token** dán vào biến `CLOUDFLARE_TUNNEL_TOKEN` trong tệp `.env`.
4. Trong tab **Public Hostname** của Tunnel, thêm rule:
   - **Domain**: `okiaconpet.cloud` (hoặc subdomain như `scanner.okiaconpet.cloud`)
   - **Service Type**: `HTTP`
   - **URL**: `web:5000` (nếu dùng `cloudflared` trong `docker-compose.yml`) hoặc `127.0.0.1:5000` (nếu chạy `cloudflared` trực tiếp trên host).

---

## 3. Khởi chạy hệ thống bằng Docker Compose

```bash
docker compose up -d --build
docker compose ps
```

Kiểm tra endpoint sức khỏe cục bộ:

```bash
curl -i http://127.0.0.1:5000/api/health
```

---

## 4. Cơ chế An toàn & Bảo mật khi Vận hành

- **Xác thực Client IP qua Cloudflare Tunnel**: `app.py` và `middleware/rate_limiter.py` chỉ đọc `CF-Connecting-IP` / `X-Forwarded-For` và `X-Forwarded-Proto` khi kết nối TCP đến từ `TRUSTED_PROXIES` (`172.28.0.0/16` hoặc `127.0.0.1/32`), chống giả mạo header khi gọi trực tiếp.
- **Giới hạn Phạm vi Mục tiêu**: `core/security/target_validator.py` chỉ cho phép `localhost`/loopback hoặc các domain nằm trong `AUTHORIZED_TARGET_DOMAINS` và chặn tuyệt đối mọi dải IP nội bộ (`10/8`, `172.16/12`, `192.168/16`), Link-Local/Cloud Metadata (`169.254.0.0/16`).
- **Xác minh Quyền sở hữu (`TARGET_VERIFICATION_REQUIRED=true`)**: Người dùng thường phải xác minh mục tiêu qua `/.well-known/pentest-verify.txt` hoặc được tài khoản `admin` phê duyệt trước khi khởi chạy phiên quét.
- **Chống Tự quét Vòng lặp (Self-Scan Guard)**: Khi mục tiêu trùng với `APP_BASE_URL` (`okiaconpet.cloud`), bộ `URLParser` tự động loại trừ các đường dẫn `/api/` và `/scans/` để không tự kích hoạt API quản trị.
