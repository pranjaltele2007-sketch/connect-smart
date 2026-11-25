"""QR code generation, HMAC-hashed pass lifecycle, and scan verification."""
import io
import json
import uuid
from datetime import timedelta

import qrcode
from flask import current_app

from app.extensions import db, socketio
from app.models import QRPass, Visitor, VisitLog, utcnow
from app.utils.helpers import classify_network
from app.utils.tokens import generate_token, hash_token


def issue_qr_pass(visitor: Visitor) -> tuple[QRPass, str]:
    """Revoke any existing active passes for visitor and issue a new expiring QR pass."""
    now = utcnow()
    QRPass.query.filter_by(visitor_id=visitor.id, is_active=True).update(
        {"is_active": False, "revoked_at": now}
    )

    raw_token = generate_token(24)
    ttl_minutes = current_app.config.get("QR_TTL_MINUTES", 1440)
    qr_pass = QRPass(
        visitor_id=visitor.id,
        token_hash=hash_token(raw_token),
        issued_at=now,
        expires_at=now + timedelta(minutes=ttl_minutes),
        is_active=True,
    )
    db.session.add(qr_pass)
    db.session.flush()
    return qr_pass, raw_token


def build_qr_payload(visitor: Visitor, raw_token: str) -> str:
    """Build compact JSON payload embedded in the QR code (supports both online & offline scan)."""
    payload = {
        "v": 1,
        "type": "smartconnect_pass",
        "token": raw_token,
        "visitor_id": visitor.visitor_uid,
        "transaction_id": visitor.transaction_id,
        "name": visitor.name,
        "mobile": visitor.mobile,
        "purpose": visitor.purpose,
        "person_to_meet": visitor.person_to_meet,
        "created_at": visitor.created_at.isoformat() if visitor.created_at else utcnow().isoformat(),
    }
    return json.dumps(payload, separators=(",", ":"))


def render_qr_png(data: str) -> bytes:
    """Render a crisp QR code PNG into an in-memory buffer."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _parse_scan_input(raw_input: str) -> tuple[str | None, dict | None]:
    """Accept either a raw token string or a SmartConnect JSON QR payload."""
    text = (raw_input or "").strip()
    if not text:
        return None, None
    if text.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data.get("token"), data
        except json.JSONDecodeError:
            return None, None
    return text, None


def verify_and_process_scan(
    raw_input: str,
    action: str = "auto",
    gate_id: int | None = None,
    guard=None,
    client_ip: str = "127.0.0.1",
    offline_sync: bool = False,
) -> tuple[bool, dict, int]:
    """
    Validate a scanned QR token (or offline JSON pass) and perform check-in / check-out.
    Returns (success, response_dict, http_status).
    """
    token, json_payload = _parse_scan_input(raw_input)
    net_type = classify_network(client_ip)
    mode = "OFFLINE_QR" if offline_sync else net_type

    if not token:
        # Handle pure offline-created visitor JSON without a server-issued token
        if json_payload and json_payload.get("type") == "offline_visitor":
            return _import_offline_visitor(json_payload, gate_id, guard, client_ip)
        return False, {"ok": False, "error": "Invalid or empty QR payload."}, 400

    token_digest = hash_token(token)
    qr_pass = QRPass.query.filter_by(token_hash=token_digest).first()
    if not qr_pass:
        if json_payload and json_payload.get("type") == "offline_visitor":
            return _import_offline_visitor(json_payload, gate_id, guard, client_ip)
        return False, {"ok": False, "error": "QR pass not recognized or forged."}, 404

    if not qr_pass.is_active or qr_pass.revoked_at is not None:
        return False, {"ok": False, "error": "This QR pass has been revoked or reissued."}, 400

    if qr_pass.is_expired():
        return False, {"ok": False, "error": "This QR pass has expired."}, 400

    visitor = Visitor.query.get(qr_pass.visitor_id)
    if not visitor:
        return False, {"ok": False, "error": "Associated visitor record not found."}, 404

    if visitor.status == "rejected":
        return False, {"ok": False, "error": "Visitor request was rejected by host."}, 403
    if visitor.status == "pending":
        return False, {"ok": False, "error": "Visitor is still awaiting host approval."}, 403

    now = utcnow()
    # Determine check-in vs check-out
    if action == "auto":
        if visitor.status == "approved":
            target_action = "check_in"
        elif visitor.status == "checked_in":
            target_action = "check_out"
        else:
            return False, {
                "ok": False,
                "error": f"Pass already completed (status: {visitor.status}).",
            }, 409
    else:
        target_action = action

    if target_action == "check_in":
        if qr_pass.used_at is not None or visitor.status == "checked_in":
            return False, {"ok": False, "error": "Duplicate scan: visitor is already checked in."}, 409
        visitor.status = "checked_in"
        visitor.checked_in_at = now
        qr_pass.used_at = now
    elif target_action == "check_out":
        if visitor.status != "checked_in":
            return False, {"ok": False, "error": "Visitor must be checked in before check-out."}, 400
        visitor.status = "checked_out"
        visitor.checked_out_at = now
        qr_pass.is_active = False
    else:
        return False, {"ok": False, "error": "Unsupported scan action."}, 400

    log = VisitLog(
        visitor_id=visitor.id,
        pass_id=qr_pass.id,
        gate_id=gate_id or (guard.gate_id if guard else None),
        actor_id=guard.id if guard else None,
        action=target_action,
        mode=mode,
        client_ip=client_ip,
        network_type=net_type,
        details=f"{target_action.replace('_', ' ').title()} via {mode}",
    )
    db.session.add(log)
    db.session.commit()

    payload = {
        "ok": True,
        "action": target_action,
        "mode": mode,
        "visitor": {
            "id": visitor.id,
            "visitor_uid": visitor.visitor_uid,
            "name": visitor.name,
            "mobile": visitor.mobile,
            "company": visitor.company,
            "purpose": visitor.purpose,
            "person_to_meet": visitor.person_to_meet,
            "status": visitor.status,
            "checked_in_at": visitor.checked_in_at.isoformat() if visitor.checked_in_at else None,
            "checked_out_at": visitor.checked_out_at.isoformat() if visitor.checked_out_at else None,
        },
    }
    socketio.emit("visitor:updated", payload)
    return True, payload, 200


def _import_offline_visitor(
    data: dict, gate_id: int | None, guard, client_ip: str
) -> tuple[bool, dict, int]:
    """Validate and import a pure offline QR visitor payload into the shared database."""
    txn_id = str(data.get("transaction_id") or "").strip()
    v_uid = str(data.get("visitor_id") or "").strip() or str(uuid.uuid4())
    name = str(data.get("name") or "").strip()
    mobile = str(data.get("mobile") or "").strip()
    purpose = str(data.get("purpose") or "Campus Visit").strip()
    meet = str(data.get("person_to_meet") or "Reception").strip()

    if not name or not mobile or not txn_id:
        return False, {"ok": False, "error": "Offline QR missing required visitor fields."}, 400

    existing = Visitor.query.filter(
        (Visitor.transaction_id == txn_id) | (Visitor.visitor_uid == v_uid)
    ).first()
    if existing:
        return False, {
            "ok": False,
            "duplicate": True,
            "error": f"Duplicate offline QR import ignored (transaction {txn_id} already recorded).",
        }, 409

    now = utcnow()
    visitor = Visitor(
        visitor_uid=v_uid,
        transaction_id=txn_id,
        name=name[:120],
        mobile=mobile[:20],
        purpose=purpose[:200],
        person_to_meet=meet[:120],
        status="checked_in",
        communication_mode="OFFLINE_QR",
        access_key_hash=hash_token(generate_token(12)),
        approved_at=now,
        checked_in_at=now,
        imported_at=now,
    )
    db.session.add(visitor)
    db.session.flush()

    log = VisitLog(
        visitor_id=visitor.id,
        gate_id=gate_id or (guard.gate_id if guard else None),
        actor_id=guard.id if guard else None,
        action="offline_sync",
        mode="OFFLINE_QR",
        client_ip=client_ip,
        network_type=classify_network(client_ip),
        details=f"Imported offline QR visitor ({txn_id})",
    )
    db.session.add(log)
    db.session.commit()

    payload = {
        "ok": True,
        "action": "offline_import_checkin",
        "mode": "OFFLINE_QR",
        "visitor": {
            "id": visitor.id,
            "visitor_uid": visitor.visitor_uid,
            "name": visitor.name,
            "mobile": visitor.mobile,
            "purpose": visitor.purpose,
            "person_to_meet": visitor.person_to_meet,
            "status": visitor.status,
        },
    }
    socketio.emit("visitor:updated", payload)
    return True, payload, 200
