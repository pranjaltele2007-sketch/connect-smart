"""Admin dashboard, user management, CSV export, and real-time network telemetry."""
import csv
import io
from flask import Blueprint, Response, current_app, jsonify, redirect, render_template, request, url_for
from sqlalchemy import func

from app.extensions import db
from app.models import Admin, Department, Gate, Visitor, VisitLog
from app.services.network_monitor import get_snapshot
from app.utils.helpers import clean_str
from app.utils.security import csrf_protect, roles_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.get("")
@roles_required("admin")
def dashboard():
    counts_rows = db.session.query(Visitor.status, func.count(Visitor.id)).group_by(Visitor.status).all()
    counts = dict(counts_rows)
    stats = {
        "total": sum(counts.values()),
        "pending": counts.get("pending", 0),
        "approved": counts.get("approved", 0),
        "checked_in": counts.get("checked_in", 0),
        "checked_out": counts.get("checked_out", 0),
        "rejected": counts.get("rejected", 0),
    }
    visitors = Visitor.query.order_by(Visitor.created_at.desc()).limit(50).all()
    logs = VisitLog.query.order_by(VisitLog.created_at.desc()).limit(25).all()
    net = get_snapshot()
    return render_template("admin_dashboard.html", stats=stats, visitors=visitors, logs=logs, net=net)


@admin_bp.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    departments = Department.query.order_by(Department.name).all()
    gates = Gate.query.order_by(Gate.name).all()

    if request.method == "POST":
        from app.utils.security import verify_csrf
        if not verify_csrf():
            return redirect(url_for("admin.users"))

        username = clean_str(request.form.get("username"), 64)
        full_name = clean_str(request.form.get("full_name"), 120)
        password = request.form.get("password") or ""
        role = request.form.get("role", "host")
        dept_id = request.form.get("department_id", type=int) or None
        gate_id = request.form.get("gate_id", type=int) or None

        if username and full_name and len(password) >= 6 and role in ("admin", "host", "security"):
            if not Admin.query.filter_by(username=username).first():
                u = Admin(
                    username=username,
                    full_name=full_name,
                    role=role,
                    department_id=dept_id,
                    gate_id=gate_id,
                )
                u.set_password(password, method=current_app.config["PASSWORD_HASH_METHOD"])
                db.session.add(u)
                db.session.commit()
        return redirect(url_for("admin.users"))

    all_users = Admin.query.order_by(Admin.role, Admin.username).all()
    return render_template("admin_users.html", users=all_users, departments=departments, gates=gates)


@admin_bp.post("/users/<int:user_id>/toggle")
@roles_required("admin")
@csrf_protect
def toggle_user(user_id: int):
    u = Admin.query.get_or_404(user_id)
    if u.username != "admin":
        u.is_active = not u.is_active
        db.session.commit()
    return redirect(url_for("admin.users"))


@admin_bp.get("/network")
@roles_required("admin")
def network_page():
    snapshot = get_snapshot()
    return render_template("admin_network.html", net=snapshot)


@admin_bp.get("/api/network")
@roles_required("admin")
def network_api():
    return jsonify({"ok": True, **get_snapshot()})


@admin_bp.get("/export.csv")
@roles_required("admin")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "UID", "Name", "Mobile", "Company", "Purpose", "Meet", "Status", "Mode", "Created"])
    for v in Visitor.query.order_by(Visitor.created_at.desc()).all():
        writer.writerow([
            v.id, v.visitor_uid, v.name, v.mobile, v.company,
            v.purpose, v.person_to_meet, v.status, v.communication_mode,
            v.created_at.isoformat() if v.created_at else "",
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=smartconnect_visitors.csv"},
    )
