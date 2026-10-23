# ĐẶC TẢ KỸ THUẬT & PHÂN CHIA MODULE HỆ THỐNG KIỂM THỬ THÂM NHẬP TỰ ĐỘNG (OWASP SCANNER)

## 1. THÔNG TIN ĐỀ TÀI
- **Tên đề tài:** Nghiên Cứu và Xây Dựng Hệ Thống Kiểm Thử Thâm Nhập Tự Động (Automated Pentest cho Web dựa vào OWASP).
- **Giảng viên hướng dẫn:** TS. Văn Thiên Hoàng.
- **Thành viên nghiên cứu:**
  1. **Nguyễn Tiến Đức** (MSSV: 2380600542 - Chủ nhiệm đề tài)
  2. **Đặng Ngọc Huy** (MSSV: 2380600794 - Thành viên)
- **Kế hoạch thời gian hoàn thiện:** 10 tuần
---

## 2. KIẾN TRÚC TỔNG THỂ & DANH MỤC CÁC MODULE

Hệ thống được thiết kế theo mô hình Clean Architecture, tách bạch giữa phần Core Engine kiểm thử, Tầng dịch vụ Web API Backend, và Giao diện người dùng Web Dashboard / CLI Terminal.

```
                      +---------------------------------------+
                      |           USER INTERFACES             |
                      |  [Web UI (Bootstrap/JS)]   [CLI Tool] |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |      WEB API & TASK QUEUE (Flask)     |
                      |   - Auth / JWT  - Async Job Worker    |
                      +-------------------+-------------------+
                                          |
                      +-------------------v-------------------+
                      |        CORE ORCHESTRATOR ENGINE       |
                      +---------+-------------------+---------+
                                |                   |
               +----------------v-----+      +------v----------------+
               |  BFS CRAWLER ENGINE  |      |   VULNERABILITY       |
               |  - Scope Filter      |      |   SCANNING MODULES    |
               |  - Form/Param Parser |      |   - BaseScanner       |
               +----------------------+      |   - Security Headers  |
                                             |   - Anti-CSRF Token   |
                                             |   - SQL Injection     |
                                             |   - Reflected XSS     |
                                             +-----------+-----------+
                                                         |
                      +----------------------------------v----+
                      |    DATA LAYER & ENCRYPTION AT-REST    |
                      |    - SQLAlchemy ORM                   |
                      |    - AES-256 Field-level Encryption   |
                      +---------------------------------------+
```

---

## 3. CHI TIẾT ĐẶC TẢ YÊU CẦU THEO TỪNG MODULE & ISSUE

### 📌 MODULE 1: CORE ARCHITECTURE & DATA SECURITY (BACKEND)
*Phụ trách chính: Nguyễn Tiến Đức (Nội dung nghiên cứu STT 1, 2)*

#### 🎯 Issue #1.1: Thiết lập cấu trúc thư mục Clean Architecture & ORM Models
- **Mục tiêu:** Xây dựng khung project phân lớp rõ ràng, quản lý dữ liệu an toàn qua ORM.
- **Yêu cầu kỹ thuật:**
  - Tổ chức cấu trúc source code:
    - `core/`: Chứa engine lõi, crawler, scanners trừu tượng.
    - `scanners/`: Chứa các module kiểm thử cụ thể (SQLi, XSS, CSRF, Headers).
    - `api/`: Controllers, Routes, Schemas cho Web API.
    - `services/`: Business logic, Background workers, Encryption services.
    - `models/`: Định nghĩa các thực thể CSDL với SQLAlchemy ORM.
    - `templates/` & `static/`: Frontend Web Dashboard.
  - Định nghĩa các thực thể Database:
    - `ScanTarget`: id, url, name, created_at.
    - `ScanSession`: id, target_id, status (PENDING, RUNNING, COMPLETED, FAILED), start_time, end_time, summary_stats.
    - `CrawledEndpoint`: id, session_id, url, method (GET/POST), params_schema (JSON).
    - `VulnerabilityFinding`: id, session_id, vuln_type, severity (INFO, LOW, MEDIUM, HIGH, CRITICAL), target_url, param, payload, evidence, cwe_id, remediation.
  - Tạo script khởi tạo database tự động.

#### 🎯 Issue #1.2: Triển khai Module mã hóa bảo vệ dữ liệu nhạy cảm At-Rest (AES-256)
- **Mục tiêu:** Đảm bảo toàn bộ payload nhạy cảm, URL nội bộ và bằng chứng quét (evidence) được mã hóa an toàn khi lưu trữ.
- **Yêu cầu kỹ thuật:**
  - Viết `EncryptionService` bằng thư viện `cryptography` (Python) sử dụng thuật toán AES-256-CBC hoặc AES-256-GCM.
  - Quản lý Master Encryption Key từ biến môi trường (`.env`).
  - Viết custom SQLAlchemy TypeDecorator (hoặc ORM listener hooks) tự động mã hóa trường `payload`, `evidence` khi INSERT/UPDATE và giải mã khi SELECT.

#### 🎯 Issue #1.3: Thu thập tập mẫu thử nghiệm & Payload Dictionary theo chuẩn OWASP
- **Mục tiêu:** Chuẩn hóa ngân hàng vector tấn công và mẫu kiểm thử an toàn có kiểm soát.
- **Yêu cầu kỹ thuật:**
  - Xây dựng từ điển payload cho SQL Injection (Error-based, Boolean-based: `' OR 1=1--`, `' AND 1=2--`, quote escape, comment markers).
  - Xây dựng từ điển payload cho Reflected XSS (`<script>alert(1)</script>`, `"><img src=x onerror=...>`, bypass cơ bản).
  - Định dạng lưu trữ: `payloads.json` hoặc cấu trúc phân cấp trong `resources/payloads/`.

---

### 📌 MODULE 2: TARGET RECON & CRAWLER ENGINE (BACKEND)
*Phụ trách chính: Đặng Ngọc Huy (Nội dung nghiên cứu STT 3)*

#### 🎯 Issue #2.1: Xây dựng thuật toán thu thập liên kết BFS & Kiểm soát phạm vi (Scope Filter)
- **Mục tiêu:** Quét đệ quy toàn bộ website mục tiêu theo cấu trúc đồ thị BFS, loại trừ vòng lặp vô hạn.
- **Yêu cầu kỹ thuật:**
  - Sử dụng `requests.Session` với Connection Pooling để tối ưu hóa hiệu năng HTTP.
  - Phân tích cú pháp HTML bằng `BeautifulSoup4` để bóc tách toàn bộ thẻ `<a href="...">`.
  - Bộ lọc Scope: Chỉ crawl các liên kết thuộc cùng Hostname/Domain mục tiêu; tự động loại bỏ các liên kết ra ngoài domain (Out-of-scope).
  - Cơ chế kiểm soát: Hỗ trợ cấu hình `max_depth` (độ sâu liên kết tối đa), `max_pages` (giới hạn trang), và `timeout`.
  - Hàng đợi FIFO (`collections.deque`) kết hợp tập `visited_urls` để chống trùng lặp và vòng lặp vô hạn.

#### 🎯 Issue #2.2: Bóc tách tham số GET/POST và Form HTML
- **Mục tiêu:** Xác định và chuẩn hóa toàn bộ bề mặt tấn công (Attack Surface).
- **Yêu cầu kỹ thuật:**
  - Bóc tách query parameters từ các URL tìm thấy (HTTP GET).
  - Phân tích cú pháp các thẻ `<form>`:
    - Thuộc tính `action` (endpoint xử lý), `method` (GET hoặc POST).
    - Toàn bộ trường đầu vào: `<input>` (type text, hidden, password, email...), `<textarea>`, `<select>`.
  - Chuẩn hóa đầu ra thành cấu trúc dữ liệu `EndpointDescriptor` để cung cấp trực tiếp cho Scanners.

---

### 📌 MODULE 3: VULNERABILITY SCANNING ENGINE (BACKEND)
*Phụ trách: Nguyễn Tiến Đức (STT 4) & Đặng Ngọc Huy (STT 5)*

#### 🎯 Issue #3.1: Thiết kế lớp trừu tượng `BaseScanner` *(Đức)*
- **Mục tiêu:** Tạo bộ khung quét đa hình, chuẩn hóa giao diện cho mọi loại scanner.
- **Yêu cầu kỹ thuật:**
  - Xây dựng Abstract Base Class `BaseScanner` chứa phương thức trừu tượng `scan(endpoint: EndpointDescriptor) -> List[Finding]`.
  - Định nghĩa cấu trúc lớp `Finding`: `vuln_name`, `severity`, `target_url`, `parameter`, `payload`, `evidence`, `cwe_id`, `remediation`.
  - Tích hợp rate limiting và xử lý lỗi network exception mềm mại (không làm sập tiến trình quét chính).

#### 🎯 Issue #3.2: Module kiểm tra cấu hình HTTP Security Headers *(Đức)*
- **Mục tiêu:** Rà quét và phát hiện các điểm yếu về cấu hình bảo mật header HTTP.
- **Yêu cầu kỹ thuật:**
  - Gửi request đến root và các endpoint chính, phân tích HTTP Response Headers.
  - Kiểm tra sự hiện diện và tham số của:
    - `Strict-Transport-Security` (HSTS): max-age, includeSubDomains.
    - `Content-Security-Policy` (CSP): Kiểm tra thiếu vắng hoặc cấu hình lỏng lẻo (`unsafe-inline`, `*`).
    - `X-Frame-Options`: Chống Clickjacking (`DENY` hoặc `SAMEORIGIN`).
    - `X-Content-Type-Options`: Bắt buộc `nosniff`.
  - Ghi nhận `Finding` với mức độ tương ứng kèm giải pháp khắc phục.

#### 🎯 Issue #3.3: Module phát hiện Anti-CSRF Token Missing *(Đức)*
- **Mục tiêu:** Kiểm tra cơ chế chống giả mạo yêu cầu chéo trang trên các form thay đổi trạng thái.
- **Yêu cầu kỹ thuật:**
  - Lọc toàn bộ các HTML Form có phương thức POST/PUT/DELETE.
  - Rà soát các trường ẩn (`<input type="hidden">`) để tìm token CSRF hợp lệ (theo pattern regex như `csrf`, `xsrf`, `token`, `authenticity_token`).
  - Gắn nhãn lỗ hổng nếu form không có token hoặc token cố định/rỗng.

#### 🎯 Issue #3.4: Module rà quét SQL Injection (Error-based & Boolean-based) *(Huy)*
- **Mục tiêu:** Tự động phát hiện lỗi tiêm mã SQL qua tham số GET và trường Form POST.
- **Yêu cầu kỹ thuật:**
  - **Error-based SQLi:** Xây dựng bộ biểu thức chính quy (Regex) toàn diện nhận diện thông báo lỗi cơ sở dữ liệu phổ biến:
    - MySQL (`You have an error in your SQL syntax`, `Warning: mysql_fetch...`)
    - PostgreSQL (`PostgreSQL query failed: ERROR...`)
    - SQLite (`SQLite/JDBCDriver`, `sqlite3.OperationalError`)
    - MSSQL / Oracle error patterns.
  - **Boolean-based SQLi:** Tiêm cặp payload nghịch đảo logic (`AND 1=1` so sánh với `AND 1=2`), so sánh độ tương đồng nội dung HTML phản hồi (Response Length, Diff Ratio, Status Code).
  - Trích xuất payload và đoạn response làm bằng chứng (Evidence).

#### 🎯 Issue #3.5: Module rà soát Reflected XSS *(Huy)*
- **Mục tiêu:** Rà quét lỗ hổng kịch bản chéo trang phản chiếu (Reflected Cross-Site Scripting).
- **Yêu cầu kỹ thuật:**
  - Gửi các giá trị độc nhất (Unique Probe Canary) như `q7x<probe>y9z` vào từng tham số GET/POST.
  - Phân tích phản hồi xem ký tự đặc biệt `<`, `>`, `"`, `'` có bị mã hóa (HTML entity encode) hay phản chiếu nguyên bản.
  - Xác định ngữ cảnh tiêm: HTML context, Attribute context, hoặc JavaScript context.
  - Sinh cảnh báo kèm bằng chứng trích xuất từ vị trí phản chiếu.

---

### 📌 MODULE 4: CORE ENGINE ORCHESTRATOR & CLI TERMINAL (BACKEND)
*Phụ trách chính: Nguyễn Tiến Đức (Nội dung nghiên cứu STT 6)*

#### 🎯 Issue #4.1: Xây dựng Bộ điều phối trung tâm (Engine Orchestrator)
- **Mục tiêu:** Tích hợp luồng thực thi tuần tự từ Crawler đến toàn bộ Scanners và lưu kết quả.
- **Yêu cầu kỹ thuật:**
  - Nhận mục tiêu quét và cấu hình -> Khởi chạy `CrawlerEngine` -> Nhận danh sách endpoints -> Đẩy dữ liệu qua danh sách `Scanners`.
  - Cơ chế lọc trùng lặp Finding (Deduplication): Tránh ghi nhận nhiều phát hiện giống hệt nhau trên cùng một tham số/URL.
  - Tích hợp lớp mã hóa At-Rest để lưu trữ findings vào cơ sở dữ liệu.
  - Báo cáo sự kiện (Event Callback) để cập nhật tiến độ cho Web Backend hoặc CLI.

#### 🎯 Issue #4.2: Xây dựng Giao diện dòng lệnh CLI Terminal
- **Mục tiêu:** Cung cấp công cụ chạy quét độc lập trực tiếp từ Terminal cho lập trình viên và DevOps.
- **Yêu cầu kỹ thuật:**
  - Xây dựng bằng `argparse` hoặc `click`.
  - Hỗ trợ các đối số:
    - `-u, --url`: URL mục tiêu.
    - `-d, --depth`: Độ sâu crawler (mặc định 2).
    - `-m, --modules`: Chỉ định module (all, sqli, xss, headers, csrf).
    - `-o, --output`: Xuất báo cáo (txt, json, pdf).
  - Hiển thị thanh tiến trình trực quan trên terminal và in bảng kết quả dạng Markdown/Text khi hoàn tất.

---

### 📌 MODULE 5: WEB BACKEND API & ASYNC TASK QUEUE (BACKEND)
*Phụ trách chính: Đặng Ngọc Huy (Nội dung nghiên cứu STT 7)*

#### 🎯 Issue #5.1: Xây dựng Hệ thống Web RESTful API (Flask + JWT)
- **Mục tiêu:** Cung cấp API phục vụ toàn bộ chức năng quản lý, quét và tra cứu kết quả.
- **Yêu cầu kỹ thuật:**
  - Triển khai xác thực và phân quyền bằng JWT hoặc Flask-Login.
  - Các endpoints chính:
    - `POST /api/auth/login`: Xác thực đăng nhập.
    - `POST /api/scans`: Khởi tạo phiên quét mới (Target URL, cấu hình).
    - `GET /api/scans`: Lấy lịch sử các phiên quét.
    - `GET /api/scans/<id>`: Lấy chi tiết phiên quét và trạng thái tiến độ hiện tại.
    - `GET /api/scans/<id>/findings`: Lấy danh sách lỗ hổng phát hiện (tự động giải mã AES-256).
    - `POST /api/scans/<id>/stop`: Hủy/Dừng phiên quét đang chạy.
  - Xác thực và kiểm tra tính hợp lệ dữ liệu đầu vào với Marshmallow Schema.

#### 🎯 Issue #5.2: Triển khai Hàng đợi tác vụ chạy ngầm (Background Worker)
- **Mục tiêu:** Thực thi các phiên quét nặng dưới nền, ngăn chặn nghẽn Web Server.
- **Yêu cầu kỹ thuật:**
  - Thiết kế ThreadPool / Background Worker quản lý tác vụ quét không chặn HTTP request.
  - Cập nhật tiến độ phần trăm (`progress: 0 -> 100%`) và trạng thái thời gian thực (`PENDING`, `CRAWLING`, `SCANNING`, `COMPLETED`, `FAILED`) vào CSDL.
  - Quản lý bắt ngoại lệ đảm bảo worker không bị crash khi mục tiêu sập mạng.

---

### 📌 MODULE 6: WEB DASHBOARD FRONTEND & TECHNICAL REPORTING
*Phụ trách: Đặng Ngọc Huy (Frontend) & Nguyễn Tiến Đức (Reporting Backend) (STT 8)*

#### 🎯 Issue #6.1 (Frontend): Thiết kế Giao diện Quản trị Dashboard *(Huy)*
- **Mục tiêu:** Cung cấp giao diện Web trực quan theo dõi tiến trình và phân tích lỗ hổng.
- **Yêu cầu kỹ thuật:**
  - Sử dụng HTML5, CSS3, Bootstrap 5 và JavaScript (Fetch API).
  - Trang Tổng quan (Dashboard): Thống kê tổng số lần quét, tỉ lệ mức độ nghiêm trọng (Critical/High/Medium/Low) sử dụng biểu đồ Chart.js.
  - Trang Tạo phiên quét (New Scan): Form nhập URL, lựa chọn Module quét, cấu hình Crawl depth.
  - Trang Chi tiết phiên quét (Scan Details): Bảng phân loại lỗ hổng với màu sắc trực quan (Badge), modal xem chi tiết Payload, URL dính lỗi, Evidence và Remediation.
  - Thanh tiến trình quét (Progress bar) tự động cập nhật qua Polling API định kỳ.

#### 🎯 Issue #6.2 (Backend): Module Trích xuất báo cáo kỹ thuật (PDF & TXT) *(Đức)*
- **Mục tiêu:** Tự động tạo báo cáo an toàn thông tin chuyên nghiệp sau khi hoàn thành phiên quét.
- **Yêu cầu kỹ thuật:**
  - Xuất báo cáo định dạng TXT: Tóm tắt danh sách lỗ hổng, URL, tham số, mức độ nghiêm trọng.
  - Xuất báo cáo định dạng PDF:
    - Bìa báo cáo, thông tin phiên kiểm thử (Thời gian, Target, Scope).
    - Tóm lược điều hành (Executive Summary) kèm biểu đồ phân bố lỗ hổng.
    - Bảng chi tiết kỹ thuật cho từng phát hiện: Tên lỗ hổng, Mã phân loại CWE/OWASP, Bằng chứng kỹ thuật, Khuyến nghị vá lỗi chuẩn mực.
  - Cung cấp API tải xuống: `GET /api/scans/<id>/report?format=pdf|txt`.

---

### 📌 MODULE 7: BENCHMARK THỰC NGHIỆM, UNIT TESTING & TỐI ƯU HÓA
*Phụ trách: Cả hai thành viên (Nội dung nghiên cứu STT 9, 10)*

#### 🎯 Issue #7.1: Triển khai Môi trường Thử nghiệm & Chạy đối chứng OWASP ZAP *(Đức & Huy)*
- **Mục tiêu:** Đánh giá năng lực phát hiện thực tế trên các ứng dụng mục tiêu chuẩn hóa (DVWA, OWASP Juice Shop).
- **Yêu cầu kỹ thuật:**
  - Dựng container Docker chạy DVWA và OWASP Juice Shop trên môi trường nội bộ.
  - Thực thi quét tự động bằng hệ thống tự phát triển và thu thập logs kết quả.
  - Chạy quét đối chứng bằng OWASP ZAP (bản tiêu chuẩn) trên cùng tập URLs.
  - Tổng hợp số liệu: Số lượng True Positive (TP), False Positive (FP), False Negative (FN).

#### 🎯 Issue #7.2: Đánh giá độ chính xác, Tối ưu & Hoàn thiện tài liệu nghiệm thu *(Đức & Huy)*
- **Mục tiêu:** Tính toán các chỉ số khoa học và hoàn chỉnh sản phẩm bàn giao.
- **Yêu cầu kỹ thuật:**
  - Tính toán các chỉ số:
    $$\text{Precision} = \frac{TP}{TP + FP}$$
    $$\text{Recall} = \frac{TP}{TP + FN}$$
    $$F_1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
  - Đo lường thời gian quét trung bình trên một mục tiêu so với OWASP ZAP.
  - Viết bộ Unit Tests (kiểm thử Crawler, bộ nhận diện Regex SQLi, XSS, mã hóa AES-256).
  - Hoàn thiện tài liệu hướng dẫn cài đặt và vận hành hệ thống.

---

## 4. MA TRẬN PHÂN CÔNG & LỘ TRÌNH 4 TUẦN

| Tuần | Nguyễn Tiến Đức | Đặng Ngọc Huy |
| :---: | :--- | :--- |
| **Tuần 1** | **Issue #1.1:** Setup Clean Arch & ORM Models<br>**Issue #1.2:** Module mã hóa At-Rest AES-256<br>**Issue #1.3:** Bộ mẫu Payload OWASP | **Issue #2.1:** BFS Crawler & Scope Filter<br>**Issue #2.2:** Bóc tách tham số GET/POST & Form |
| **Tuần 2** | **Issue #3.1:** BaseScanner trừu tượng<br>**Issue #3.2:** Scanner Security Headers<br>**Issue #3.3:** Scanner Anti-CSRF Token | **Issue #3.4:** Scanner SQL Injection (Error & Boolean)<br>**Issue #3.5:** Scanner Reflected XSS |
| **Tuần 3** | **Issue #4.1:** Core Engine Orchestrator & Dedup<br>**Issue #4.2:** Giao diện dòng lệnh CLI Terminal | **Issue #5.1:** Hệ thống Web API Flask + JWT<br>**Issue #5.2:** Hàng đợi tác vụ quét chạy ngầm |
| **Tuần 4** | **Issue #6.2:** Module xuất báo cáo PDF / TXT<br>**Issue #7.1 & #7.2:** Benchmark với OWASP ZAP & Báo cáo | **Issue #6.1:** Web Dashboard Frontend (Bootstrap + Chart.js)<br>**Issue #7.1 & #7.2:** Benchmark với OWASP ZAP & Báo cáo |
