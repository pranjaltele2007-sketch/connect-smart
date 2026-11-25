"""Host approval dashboard routes."""
from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from app.extensions import db, socketio
from app.models import QRPass, Visitor, VisitLog, utcnow
from app.utils.helpers import classify_network, get_client_ip
from app.utils.security import csrf_protect, current_user, roles_required

host_bp = Blueprint("host", __name__, url_prefix="/host")


@host_bp.get("")
@roles_required("host", "admin")
def dashboard():
    user = current_user()
    query = Visitor.query.order_by(Visitor.created_at.desc())
    if user.role == "host" and user.department_id:
        query = query.filter(
            (Visitor.department_id == user.department_id) | (Visitor.host_id == user.id) | (Visitor.department_id.is_(None))
        )
    visitors = query.limit(100).all()
    return render_template("host_dashboard.html", visitors=visitors)


@host_bp.post("/visitors/<int:visitor_id>/approve")
@roles_required("host", "admin")
@csrf_protect
def approve_visitor(visitor_id: int):
    visitor = Visitor.query.get_or_404(visitor_id)
    user = current_user()
    if visitor.status not in ("pending", "rejected"):
        if request.is_json:
            return jsonify({"ok": False, "error": f"Cannot approve visitor in status {visitor.status}"}), 400
        return redirect(url_for("host.dashboard"))

    visitor.status = "approved"
    visitor.host_id = user.id
    visitor.approved_at = utcnow()
    client_ip = get_client_ip(request)
    net_type = classify_network(client_ip)
    db.session.add(VisitLog(
        visitor_id=visitor.id,
        actor_id=user.id,
        action="approve",
        mode=net_type,
        client_ip=client_ip,
        network_type=net_type,
        details=f"Approved by {user.full_name}",
    ))
    db.session.commit()

    payload = {"ok": True, "action": "approve", "visitor": {"id": visitor.id, "name": visitor.name, "status": visitor.status}}
    socketio.emit("visitor:updated", payload)
    if request.is_json:
        return jsonify(payload)
    return redirect(url_for("host.dashboard"))


@host_bp.post("/visitors/<int:visitor_id>/reject")
@roles_required("host", "admin")
@csrf_protect
def reject_visitor(visitor_id: int):
    visitor = Visitor.query.get_or_404(visitor_id)
    user = current_user()
    visitor.status = "rejected"
    visitor.host_id = user.id
    QRPass.query.filter_by(visitor_id=visitor.id, is_active=True).update(
        {"is_active": False, "revoked_at": utcnow()}
    )
    client_ip = get_client_ip(request)
    net_type = classify_network(client_ip)
    db.session.add(VisitLog(
        visitor_id=visitor.id,
        actor_id=user.id,
        action="reject",
        mode=net_type,
        client_ip=client_ip,
        network_type=net_type,
        details=f"Rejected by {user.full_name}",
    ))
    db.session.commit()

    payload = {"ok": True, "action": "reject", "visitor": {"id": visitor.id, "name": visitor.name, "status": visitor.status}}
    socketio.emit("visitor:updated", payload)
    if request.is_json:
        return jsonify(payload)
    return redirect(url_for("host.dashboard"))
