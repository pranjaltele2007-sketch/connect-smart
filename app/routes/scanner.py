"""Security guard scanner and offline queue sync API routes."""
from flask import Blueprint, current_app, jsonify, render_template, request

from app.models import Gate, VisitLog
from app.services.qr_service import verify_and_process_scan
from app.utils.helpers import get_client_ip
from app.utils.security import csrf_protect, current_user, roles_required

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.get("/scanner")
@roles_required("security", "admin")
def scanner_page():
    gates = Gate.query.filter_by(is_active=True).all()
    recent_logs = VisitLog.query.order_by(VisitLog.created_at.desc()).limit(15).all()
    return render_template("scanner.html", gates=gates, recent_logs=recent_logs)


@scanner_bp.post("/api/scan")
@roles_required("security", "admin")
@csrf_protect
def api_scan():
    data = request.get_json(silent=True) or {}
    raw_qr = data.get("qr_data") or data.get("token") or ""
    action = data.get("action") or "auto"
    gate_id = data.get("gate_id")
    guard = current_user()
    client_ip = get_client_ip(request)

    _, result, code = verify_and_process_scan(
        raw_input=raw_qr,
        action=action,
        gate_id=gate_id,
        guard=guard,
        client_ip=client_ip,
        offline_sync=False,
    )
    return jsonify(result), code


@scanner_bp.post("/api/sync")
@roles_required("security", "admin")
@csrf_protect
def api_sync():
    """Batch sync queued offline scans from guard IndexedDB."""
    data = request.get_json(silent=True) or {}
    items = data.get("items") or []
    max_batch = current_app.config.get("SYNC_MAX_BATCH", 100)
    if not isinstance(items, list) or len(items) > max_batch:
        return jsonify({"ok": False, "error": f"Batch must be a list of <= {max_batch} items."}), 400

    guard = current_user()
    client_ip = get_client_ip(request)
    results = []
    for item in items:
        local_id = item.get("local_id")
        raw_qr = item.get("qr_data") or ""
        action = item.get("action") or "auto"
        gate_id = item.get("gate_id")
        ok, res, code = verify_and_process_scan(
            raw_input=raw_qr,
            action=action,
            gate_id=gate_id,
            guard=guard,
            client_ip=client_ip,
            offline_sync=True,
        )
        results.append({
            "local_id": local_id,
            "ok": ok,
            "status": code,
            "duplicate": res.get("duplicate", False) or code == 409,
            "error": res.get("error"),
            "visitor": res.get("visitor"),
        })

    return jsonify({"ok": True, "synced": len(results), "results": results}), 200
