"""Public routes: landing, healthcheck, visitor registration, QR pass view, and Service Worker."""
import uuid
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from app.extensions import db, socketio
from app.models import Department, QRPass, Visitor, VisitLog
from app.services.qr_service import build_qr_payload, issue_qr_pass, render_qr_png
from app.utils.helpers import classify_network, clean_str, get_client_ip, is_valid_mobile
from app.utils.security import check_register_rate_limit, csrf_protect, current_user
from app.utils.tokens import generate_token, hash_token, verify_token_hash

public_bp = Blueprint("public", __name__)


@public_bp.get("/")
def index():
    user = current_user()
    if user:
        if user.role == "admin":
            return redirect(url_for("admin.dashboard"))
        if user.role == "host":
            return redirect(url_for("host.dashboard"))
        if user.role == "security":
            return redirect(url_for("scanner.scanner_page"))
    return render_template("index.html")


@public_bp.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "SmartConnect",
        "network_mode": current_app.config.get("NETWORK_MODE", "LAN"),
    }), 200


@public_bp.route("/register", methods=["GET", "POST"])
def register():
    departments = Department.query.order_by(Department.name).all()
    if request.method == "GET":
        return render_template("register.html", departments=departments)

    client_ip = get_client_ip(request)
    if not check_register_rate_limit(client_ip):
        return render_template(
            "register.html",
            departments=departments,
            error="Too many registrations from this device. Please wait a few minutes.",
        ), 429

    # CSRF check
    from app.utils.security import verify_csrf
    if not verify_csrf():
        abort(403, description="Invalid or missing CSRF token.")

    name = clean_str(request.form.get("name"), 120)
    mobile = clean_str(request.form.get("mobile"), 20)
    email = clean_str(request.form.get("email"), 120)
    company = clean_str(request.form.get("company"), 120)
    purpose = clean_str(request.form.get("purpose"), 200)
    person_to_meet = clean_str(request.form.get("person_to_meet"), 120)
    dept_id = request.form.get("department_id", type=int)

    if not name or not is_valid_mobile(mobile) or not purpose or not person_to_meet:
        return render_template(
            "register.html",
            departments=departments,
            error="Please provide a valid name, mobile number, purpose, and person to meet.",
        ), 400

    visitor_uid = str(uuid.uuid4())
    txn_id = f"TXN-{visitor_uid[:8].upper()}"
    access_key = generate_token(16)
    net_type = classify_network(client_ip)

    visitor = Visitor(
        visitor_uid=visitor_uid,
        transaction_id=txn_id,
        name=name,
        mobile=mobile,
        email=email,
        company=company,
        purpose=purpose,
        person_to_meet=person_to_meet,
        department_id=dept_id,
        status="pending",
        communication_mode=net_type,
        access_key_hash=hash_token(access_key),
    )
    db.session.add(visitor)
    db.session.flush()

    qr_pass, raw_token = issue_qr_pass(visitor)
    db.session.add(VisitLog(
        visitor_id=visitor.id,
        pass_id=qr_pass.id,
        action="register",
        mode=net_type,
        client_ip=client_ip,
        network_type=net_type,
        details=f"Registered via {net_type}",
    ))
    db.session.commit()

    socketio.emit("visitor:registered", {
        "id": visitor.id,
        "visitor_uid": visitor.visitor_uid,
        "name": visitor.name,
        "purpose": visitor.purpose,
        "person_to_meet": visitor.person_to_meet,
        "status": visitor.status,
        "mode": net_type,
    })

    qr_payload = build_qr_payload(visitor, raw_token)
    return render_template(
        "pass.html",
        visitor=visitor,
        qr_pass=qr_pass,
        raw_token=raw_token,
        qr_payload=qr_payload,
        access_key=access_key,
        newly_created=True,
    )


@public_bp.get("/pass/<visitor_uid>")
def view_pass(visitor_uid: str):
    visitor = Visitor.query.filter_by(visitor_uid=visitor_uid).first_or_404()
    key = request.args.get("key", "")
    staff = current_user()
    if not staff:
        if not key or not verify_token_hash(key, visitor.access_key_hash):
            abort(403, description="Valid access key required to view this pass.")

    qr_pass = QRPass.query.filter_by(visitor_id=visitor.id, is_active=True).order_by(QRPass.id.desc()).first()
    return render_template(
        "pass.html",
        visitor=visitor,
        qr_pass=qr_pass,
        raw_token=None,
        qr_payload=None,
        access_key=key,
        newly_created=False,
    )


@public_bp.post("/pass/<visitor_uid>/reissue")
@csrf_protect
def reissue_pass(visitor_uid: str):
    visitor = Visitor.query.filter_by(visitor_uid=visitor_uid).first_or_404()
    key = request.form.get("access_key", "")
    staff = current_user()
    if not staff and (not key or not verify_token_hash(key, visitor.access_key_hash)):
        abort(403, description="Valid access key required.")

    qr_pass, raw_token = issue_qr_pass(visitor)
    client_ip = get_client_ip(request)
    db.session.add(VisitLog(
        visitor_id=visitor.id,
        pass_id=qr_pass.id,
        action="revoke",
        mode=classify_network(client_ip),
        client_ip=client_ip,
        network_type=classify_network(client_ip),
        details="Reissued QR pass (previous pass revoked)",
    ))
    db.session.commit()

    qr_payload = build_qr_payload(visitor, raw_token)
    return render_template(
        "pass.html",
        visitor=visitor,
        qr_pass=qr_pass,
        raw_token=raw_token,
        qr_payload=qr_payload,
        access_key=key,
        newly_created=True,
    )


@public_bp.get("/qr/image")
def qr_image():
    """Render a QR PNG for the given payload query parameter."""
    data = request.args.get("data", "")
    if not data or len(data) > 2048:
        abort(400)
    png_bytes = render_qr_png(data)
    return Response(
        png_bytes,
        mimetype="image/png",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@public_bp.get("/sw.js")
def service_worker():
    return send_from_directory(
        current_app.static_folder,
        "sw.js",
        mimetype="application/javascript",
    )
