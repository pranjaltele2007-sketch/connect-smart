"""Staff authentication routes with lockout protection."""
from datetime import timedelta
from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from app.extensions import db
from app.models import Admin, utcnow
from app.utils.security import verify_csrf

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    if not verify_csrf():
        return render_template("login.html", error="Session expired. Please try again."), 403

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    user = Admin.query.filter_by(username=username).first()

    if user and user.is_locked():
        return render_template(
            "login.html",
            error="Account temporarily locked due to failed attempts. Please wait a few minutes.",
        ), 423

    if not user or not user.is_active or not user.check_password(password):
        if user:
            user.failed_attempts += 1
            max_attempts = current_app.config.get("LOGIN_MAX_ATTEMPTS", 5)
            lock_sec = current_app.config.get("LOGIN_LOCK_SECONDS", 300)
            if user.failed_attempts >= max_attempts:
                user.locked_until = utcnow() + timedelta(seconds=lock_sec)
            db.session.commit()
        return render_template("login.html", error="Invalid username or password."), 401

    # Success: reset lockout counters & bind session
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    csrf_tok = session.get("_csrf_token")
    session.clear()
    if csrf_tok:
        session["_csrf_token"] = csrf_tok
    session["user_id"] = user.id
    session["role"] = user.role
    session.permanent = True

    next_url = request.args.get("next")
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)

    if user.role == "admin":
        return redirect(url_for("admin.dashboard"))
    if user.role == "host":
        return redirect(url_for("host.dashboard"))
    return redirect(url_for("scanner.scanner_page"))


@auth_bp.post("/logout")
def logout():
    if not verify_csrf():
        return redirect(url_for("public.index"))
    session.clear()
    return redirect(url_for("public.index"))
