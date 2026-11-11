"""
Application factory cho Web Backend API - Issue #5.1/#5.2.
"""

from __future__ import annotations

from typing import Any

from flask import Flask, jsonify
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from config.config import (
    Config,
    get_config,
    validate_production_secrets,
    validate_single_process_config,
)
from controllers.auth_controller import auth_blueprint
from controllers.scan_controller import scan_blueprint
from middleware.error_handler import register_error_handlers
from middleware.rate_limiter import init_rate_limiter
from models.base import get_session_factory, init_db
from services.scan_service import configure_worker_session_factory


def create_app(config: type[Config] | dict[str, Any] | None = None) -> Flask:
    """Tạo Flask app, database, middleware và API blueprints."""
    app = Flask(__name__)
    config_object = config if config is not None and not isinstance(config, dict) else get_config()
    app.config.from_object(config_object)
    if isinstance(config, dict):
        app.config.update(config)

    validate_single_process_config(app.config.get("WORKER_PROCESSES", 1))

    # Fix review (Critical): ở production phải có secret mạnh, nếu không thì dừng khởi động.
    env = str(app.config.get("APP_ENV", "development")).lower()
    if env == "production" and not app.config.get("TESTING"):
        validate_production_secrets(
            app.config.get("SECRET_KEY"),
            app.config.get("JWT_SECRET_KEY"),
        )

    engine = init_db(app.config["SQLALCHEMY_DATABASE_URI"])
    session_factory: sessionmaker[Session] = get_session_factory(engine)
    app.extensions["database_engine"] = engine
    app.extensions["database_session_factory"] = session_factory
    configure_worker_session_factory(session_factory)

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(scan_blueprint)
    register_error_handlers(app)
    init_rate_limiter(
        app,
        limit=int(app.config.get("RATE_LIMIT_MAX_REQUESTS", 60)),
        window_seconds=int(app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)),
        trusted_proxies=app.config.get("TRUSTED_PROXIES"),
    )

    @app.get("/api/health")
    def health() -> ResponseReturnValue:
        return jsonify(status="ok"), 200

    # Fix review (High - độ tin cậy): khôi phục các phiên quét còn dang dở khi khởi động lại.
    if not app.config.get("TESTING"):
        try:
            from tasks.recovery_tasks import recover_pending_scans

            recovered = recover_pending_scans(session_factory)
            if recovered:
                app.logger.info("Đã đưa lại %d phiên quét dang dở vào hàng đợi.", recovered)
        except Exception:  # noqa: BLE001 - lỗi khôi phục không được chặn việc khởi động
            app.logger.exception("Không thể khôi phục hàng đợi scan khi khởi động.")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
