"""
Application factory cho Web Backend API - Issue #5.1/#5.2.
"""

from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, render_template
from flask.typing import ResponseReturnValue
from sqlalchemy.orm import Session, sessionmaker

from config.config import Config, get_config
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
    )

    @app.get("/api/health")
    def health() -> ResponseReturnValue:
        return jsonify(status="ok"), 200

    # Issue #6.1: serve the dashboard and scan detail pages.
    @app.get("/")
    def dashboard() -> str:
        return render_template("dashboard.html")

    @app.get("/scans/<int:session_id>")
    def scan_detail(session_id: int) -> str:
        return render_template("scan_detail.html", session_id=session_id)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)