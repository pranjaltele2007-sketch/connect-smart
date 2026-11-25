"""SmartConnect Flask application factory with speed optimizations, security headers, and CLI."""
import gzip
import time
import click
from flask import Flask, g, request
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from werkzeug.middleware.proxy_fix import ProxyFix

from config import get_config
from app.extensions import db, migrate, socketio
from app.services.network_monitor import record_request
from app.utils.helpers import classify_network, get_client_ip
from app.utils.security import current_user, get_csrf_token


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)
    cfg = get_config(config_name)
    app.config.from_object(cfg)

    if app.config.get("ENV_NAME") == "production" and not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY environment variable is required in production.")

    if app.config.get("BEHIND_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    if app.config.get("SQLALCHEMY_DATABASE_URI") in ("sqlite://", "sqlite:///:memory:"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "poolclass": StaticPool,
            "connect_args": {"check_same_thread": False},
        }

    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(
        app,
        async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "threading"),
        cors_allowed_origins=app.config.get("CORS_ORIGINS") or "*",
        ping_interval=15,
        ping_timeout=10,
    )

    # Enable SQLite WAL & memory cache for high concurrency & speed
    if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite:"):
        with app.app_context():
            @event.listens_for(db.engine, "connect")
            def _set_sqlite_pragmas(dbapi_conn, _conn_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute("PRAGMA cache_size=-64000;")
                cursor.execute("PRAGMA temp_store=MEMORY;")
                cursor.execute("PRAGMA foreign_keys=ON;")
                cursor.close()

    # Register blueprints & Socket.IO events
    from app.routes.public import public_bp
    from app.routes.auth import auth_bp
    from app.routes.host import host_bp
    from app.routes.scanner import scanner_bp
    from app.routes.admin import admin_bp
    from app.sockets import events as _socket_events  # noqa: F401

    app.register_blueprint(public_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(host_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(admin_bp)

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": get_csrf_token,
            "current_user": current_user(),
            "network_mode": app.config.get("NETWORK_MODE", "LAN"),
        }

    @app.before_request
    def start_timer():
        g._req_start = time.perf_counter()

    @app.after_request
    def apply_headers_gzip_and_telemetry(response):
        # 1. Measure latency & record telemetry (skip static/health noise)
        start = getattr(g, "_req_start", None)
        if start is not None and not request.path.startswith("/static/"):
            latency_ms = (time.perf_counter() - start) * 1000.0
            ip = get_client_ip(request)
            net_type = classify_network(ip)
            record_request(request.method, request.path, response.status_code, latency_ms, ip, net_type)

        # 2. Security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # 3. Static asset caching
        if request.path.startswith("/static/") and response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=86400"

        # 4. Lightweight Gzip compression for fast LAN/WAN delivery
        accept_enc = request.headers.get("Accept-Encoding", "")
        if (
            "gzip" in accept_enc.lower()
            and not response.direct_passthrough
            and "Content-Encoding" not in response.headers
            and 200 <= response.status_code < 300
            and response.mimetype in ("text/html", "application/json", "text/css", "application/javascript")
        ):
            raw = response.get_data()
            if len(raw) > 512:
                compressed = gzip.compress(raw, compresslevel=6)
                response.set_data(compressed)
                response.headers["Content-Encoding"] = "gzip"
                response.headers["Content-Length"] = str(len(compressed))
                response.headers["Vary"] = "Accept-Encoding"

        return response

    # CLI commands expected by Procfile & render.yaml
    @app.cli.command("init-db")
    def init_db_cmd():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables initialized.")

    @app.cli.command("seed")
    @click.option("--demo/--no-demo", default=True, help="Include demo staff and sample visitors.")
    def seed_cmd(demo: bool):
        """Seed departments, gates, admin, and optional demo accounts."""
        from app.utils.seed import seed_database
        db.create_all()
        seed_database(demo=demo)
        click.echo(f"Database seeded (demo={demo}).")

    return app
