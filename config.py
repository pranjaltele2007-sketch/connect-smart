"""
config.py - central configuration for SmartConnect.

Every tunable value lives here and can be overridden with an environment
variable (or a `.env` file, see `.env.example`).  Nothing secret is hard-coded:
in production the app refuses to start without SECRET_KEY.
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

# Load variables from .env (if the file exists) into os.environ.
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _database_url() -> str:
    """SQLite by default; any SQLAlchemy URL (e.g. PostgreSQL) via DATABASE_URL."""
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        return "sqlite:///" + (INSTANCE_DIR / "smartconnect.db").as_posix()
    # Render/Heroku give "postgres://", SQLAlchemy 2 needs "postgresql://".
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return url


def _dev_secret_key() -> str:
    """Development only: create a random key once and keep it in instance/."""
    key_file = INSTANCE_DIR / "dev_secret.key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    return key


class BaseConfig:
    ENV_NAME = "base"
    DEBUG = False
    TESTING = False

    SECRET_KEY = os.getenv("SECRET_KEY")
    # Extra secret mixed into QR-token hashes (falls back to SECRET_KEY).
    QR_HASH_PEPPER = os.getenv("QR_HASH_PEPPER")

    # ---- Database -------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # ---- Sessions / cookies --------------------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=env_int("SESSION_HOURS", 8))
    MAX_CONTENT_LENGTH = 256 * 1024  # reject request bodies > 256 KB

    # ---- Passwords & login protection ------------------------------------
    PASSWORD_HASH_METHOD = "pbkdf2:sha256:150000"
    LOGIN_MAX_ATTEMPTS = env_int("LOGIN_MAX_ATTEMPTS", 5)
    LOGIN_LOCK_SECONDS = env_int("LOGIN_LOCK_SECONDS", 300)
    REGISTER_RATE_LIMIT = env_int("REGISTER_RATE_LIMIT", 10)      # requests ...
    REGISTER_RATE_WINDOW = env_int("REGISTER_RATE_WINDOW", 600)   # ... per N seconds

    # ---- QR passes ---------------------------------------------------------
    QR_TTL_MINUTES = env_int("QR_TTL_MINUTES", 24 * 60)

    # ---- Offline sync ------------------------------------------------------
    SYNC_MAX_BATCH = 100
    SYNC_MAX_AGE_HOURS = env_int("SYNC_MAX_AGE_HOURS", 24)

    # ---- Time ------------------------------------------------------------
    APP_TIMEZONE = os.getenv("APP_TIMEZONE", "Asia/Kolkata")

    # ---- Networking ------------------------------------------------------
    NETWORK_MODE = os.getenv("NETWORK_MODE", "LAN").upper()  # label: LAN or WAN
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = env_int("PORT", 5000)
    BEHIND_PROXY = env_bool("BEHIND_PROXY", False)  # True on Render/Nginx
    FORCE_HTTPS = env_bool("FORCE_HTTPS", False)
    LAN_HTTPS = env_bool("LAN_HTTPS", False)  # serve self-signed HTTPS on LAN
    SOCKETIO_ASYNC_MODE = os.getenv("SOCKETIO_ASYNC_MODE", "threading")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "")  # comma-separated, empty = same origin

    # ---- Monitoring ------------------------------------------------------
    COMM_LOG_ENABLED = True
    COMM_LOG_RETENTION_DAYS = env_int("COMM_LOG_RETENTION_DAYS", 30)


class DevelopmentConfig(BaseConfig):
    ENV_NAME = "development"
    DEBUG = env_bool("FLASK_DEBUG", False)
    SECRET_KEY = os.getenv("SECRET_KEY") or _dev_secret_key()


class ProductionConfig(BaseConfig):
    ENV_NAME = "production"
    SESSION_COOKIE_SECURE = True
    FORCE_HTTPS = env_bool("FORCE_HTTPS", True)
    BEHIND_PROXY = env_bool("BEHIND_PROXY", True)
    NETWORK_MODE = os.getenv("NETWORK_MODE", "WAN").upper()


class TestingConfig(BaseConfig):
    ENV_NAME = "testing"
    TESTING = True
    SECRET_KEY = "test-secret-key-not-for-real-use"
    PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000"  # fast hashing for tests only
    LOGIN_MAX_ATTEMPTS = 5
    REGISTER_RATE_LIMIT = 1000
    # Pin the network settings so a developer's real .env can never change test results.
    NETWORK_MODE = "LAN"
    FORCE_HTTPS = False
    BEHIND_PROXY = False
    LAN_HTTPS = False
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # overridden by the test fixtures
    SQLALCHEMY_ENGINE_OPTIONS = {}


_CONFIGS = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name=None):
    name = (name or os.getenv("APP_ENV") or os.getenv("FLASK_ENV") or "development").lower()
    return _CONFIGS.get(name, DevelopmentConfig)
