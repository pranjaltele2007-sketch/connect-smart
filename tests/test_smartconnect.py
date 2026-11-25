"""Comprehensive pytest suite for SmartConnect (auth, QR lifecycle, LAN/WAN, offline sync)."""
import json
import re
from datetime import timedelta
import pytest

from app import create_app
from app.extensions import db
from app.models import Admin, QRPass, Visitor, utcnow
from app.utils.helpers import classify_network
from app.utils.seed import seed_database


@pytest.fixture()
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        seed_database(demo=True)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def _get_csrf(client, path="/login"):
    resp = client.get(path)
    m = re.search(r'name="csrf_token" value="([^"]+)"', resp.data.decode("utf-8"))
    if m:
        return m.group(1)
    m2 = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.data.decode("utf-8"))
    return m2.group(1) if m2 else ""


def _login(client, username, password):
    csrf = _get_csrf(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
        follow_redirects=False,
    )


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_lan_vs_wan_classification():
    assert classify_network("127.0.0.1") == "LAN"
    assert classify_network("192.168.1.42") == "LAN"
    assert classify_network("10.157.99.49") == "LAN"
    assert classify_network("172.16.0.5") == "LAN"
    assert classify_network("8.8.8.8") == "WAN"
    assert classify_network("1.1.1.1") == "WAN"


def test_visitor_registration_and_qr_flow(app, client):
    csrf = _get_csrf(client, "/register")
    res = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "name": "Test Visitor",
            "mobile": "9876543210",
            "company": "TestCorp",
            "person_to_meet": "Prof. Vijay Andhale",
            "purpose": "Project Review",
        },
    )
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Test Visitor" in html

    # Extract QR payload from img src
    m = re.search(r'/qr/image\?data=([^"]+)"', html)
    assert m is not None
    from urllib.parse import unquote
    qr_json = unquote(m.group(1))
    payload = json.loads(qr_json)
    raw_token = payload["token"]

    # Ensure raw token is NOT stored in DB
    with app.app_context():
        p = QRPass.query.order_by(QRPass.id.desc()).first()
        assert p.token_hash != raw_token

    # Guard cannot check in before host approves
    _login(client, "security1", "Security@123")
    guard_csrf = _get_csrf(client, "/scanner")
    scan_pending = client.post(
        "/api/scan",
        json={"qr_data": qr_json},
        headers={"X-CSRF-Token": guard_csrf},
    )
    assert scan_pending.status_code == 403

    # Host approves
    _login(client, "host1", "Host@12345")
    host_csrf = _get_csrf(client, "/host")
    with app.app_context():
        v = Visitor.query.filter_by(name="Test Visitor").first()
        vid = v.id
    app_res = client.post(
        f"/host/visitors/{vid}/approve",
        data={"csrf_token": host_csrf},
        follow_redirects=True,
    )
    assert app_res.status_code == 200

    # Guard checks in
    _login(client, "security1", "Security@123")
    guard_csrf = _get_csrf(client, "/scanner")
    ci = client.post("/api/scan", json={"qr_data": qr_json}, headers={"X-CSRF-Token": guard_csrf})
    assert ci.status_code == 200
    assert ci.get_json()["action"] == "check_in"

    # Duplicate check-in fails
    dup = client.post(
        "/api/scan",
        json={"qr_data": qr_json, "action": "check_in"},
        headers={"X-CSRF-Token": guard_csrf},
    )
    assert dup.status_code == 409

    # Check-out succeeds
    co = client.post("/api/scan", json={"qr_data": qr_json}, headers={"X-CSRF-Token": guard_csrf})
    assert co.status_code == 200
    assert co.get_json()["action"] == "check_out"


def test_offline_qr_sync_and_duplicate_guard(client):
    _login(client, "security1", "Security@123")
    csrf = _get_csrf(client, "/scanner")
    offline_payload = json.dumps({
        "type": "offline_visitor",
        "visitor_id": "off-uid-101",
        "transaction_id": "OFF-TXN-101",
        "name": "Offline Guest",
        "mobile": "9123456789",
        "purpose": "Workshop",
        "person_to_meet": "Prof. Vijay Andhale",
    })
    res = client.post(
        "/api/sync",
        json={"items": [
            {"local_id": 1, "qr_data": offline_payload},
            {"local_id": 2, "qr_data": offline_payload},
        ]},
        headers={"X-CSRF-Token": csrf},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["results"][0]["ok"] is True
    assert data["results"][1]["ok"] is False
    assert data["results"][1]["duplicate"] is True


def test_login_lockout_and_role_protection(client):
    # Guard cannot access admin
    _login(client, "security1", "Security@123")
    assert client.get("/admin").status_code == 403

    # 5 bad passwords lock account
    client.post("/logout", data={"csrf_token": _get_csrf(client, "/scanner")})
    for _ in range(5):
        _login(client, "host2", "WrongPass!")
    locked = _login(client, "host2", "Host@12345")
    assert locked.status_code == 423


def test_admin_dashboard_and_network_telemetry(client):
    _login(client, "admin", "Admin@123")
    assert client.get("/admin").status_code == 200
    assert client.get("/admin/network").status_code == 200
    net = client.get("/admin/api/network").get_json()
    assert net["ok"] is True
    assert net["total_requests"] >= 1
    csv_res = client.get("/admin/export.csv")
    assert csv_res.status_code == 200
    assert "smartconnect_visitors.csv" in csv_res.headers.get("Content-Disposition", "")
