FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Cài đặt font Unicode DejaVu phục vụ kết xuất báo cáo PDF tiếng Việt và libpq cho PostgreSQL
RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-dejavu-core \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt gunicorn>=22.0.0 psycopg2-binary>=2.9.9

COPY . .

# Chạy dưới tài khoản non-root an toàn và tạo sẵn thư mục lưu báo cáo / dữ liệu
RUN useradd --create-home --shell /sbin/nologin scanner \
    && mkdir -p /app/reports/pdf /app/reports/txt /app/instance \
    && chown -R scanner:scanner /app

USER scanner

EXPOSE 5000

# Duy trì WORKER_PROCESSES=1 kèm đa luồng để đồng bộ hàng đợi, stop_event và rate limiter
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", "--bind", "0.0.0.0:5000", "app:create_app()"]
