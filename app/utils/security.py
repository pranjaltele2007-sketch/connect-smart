"""Authentication, role authorization, CSRF protection, and rate limiting."""
from collections import defaultdict, deque
from functools import wraps
from threading import Lock
import hmac
import secrets
import time

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

from app.models import Admin

_rate_lock = Lock()
_register_hits: dict[str, deque] = defaultdict(deque)


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def verify_csrf() -> bool:
    """Verify CSRF token from X-CSRF-Token header or form field."""
    expected = session.get("_csrf_token")
    if not expected:
        return False
    provided = (
        request.headers.get("X-CSRF-Token")
        or request.form.get("csrf_token")
        or (request.get_json(silent=True) or {}).get("csrf_token")
        or ""
    )
    return bool(provided) and hmac.compare_digest(str(expected), str(provided))


def csrf_protect(fn):
    """Require valid CSRF token on state-changing requests."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not verify_csrf():
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Invalid or missing CSRF token."}), 403
                abort(403, description="Invalid or missing CSRF token.")
        return fn(*args, **kwargs)
    return wrapper


def current_user() -> Admin | None:
    if hasattr(g, "_current_user"):
        return g._current_user
    uid = session.get("user_id")
    if not uid:
        g._current_user = None
        return None
    user = Admin.query.get(uid)
    if not user or not user.is_active:
        session.clear()
        g._current_user = None
        return None
    g._current_user = user
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Authentication required."}), 401
            return redirect(url_for("auth.login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def roles_required(*roles: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Authentication required."}), 401
                return redirect(url_for("auth.login", next=request.path))
            if user.role not in roles:
                if request.is_json or request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Forbidden: insufficient role."}), 403
                abort(403, description="You do not have permission to access this page.")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def check_register_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if rate limit exceeded."""
    limit = current_app.config.get("REGISTER_RATE_LIMIT", 10)
    window = current_app.config.get("REGISTER_RATE_WINDOW", 600)
    now = time.time()
    with _rate_lock:
        q = _register_hits[client_ip]
        while q and (now - q[0]) > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True
