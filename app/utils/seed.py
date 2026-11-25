"""Database seeding for departments, gates, admin, and optional demo accounts."""
import os
import uuid
from datetime import timedelta

from flask import current_app

from app.extensions import db
from app.models import Admin, Department, Gate, QRPass, Visitor, VisitLog, utcnow
from app.utils.tokens import generate_token, hash_token


def seed_database(demo: bool = True) -> None:
    """Idempotently seed departments, gates, admin, and optional demo accounts."""
    pw_method = current_app.config.get("PASSWORD_HASH_METHOD", "pbkdf2:sha256:150000")

    # 1. Departments
    depts_data = [
        ("Computer Science & Engg", "CSE", "Block A - 2nd Floor"),
        ("Electronics & Comm", "ECE", "Block B - 1st Floor"),
        ("Administration", "ADMIN", "Main Building - Ground"),
        ("Mechanical Engg", "MECH", "Workshop Block"),
    ]
    dept_map = {}
    for name, code, floor in depts_data:
        dept = Department.query.filter_by(code=code).first()
        if not dept:
            dept = Department(name=name, code=code, floor=floor)
            db.session.add(dept)
            db.session.flush()
        dept_map[code] = dept

    # 2. Gates
    gates_data = [
        ("Main Entrance Gate", "GATE-1", "Main Campus Road"),
        ("North Academic Gate", "GATE-2", "Block A Lobby"),
    ]
    gate_map = {}
    for name, code, loc in gates_data:
        gate = Gate.query.filter_by(code=code).first()
        if not gate:
            gate = Gate(name=name, code=code, location=loc)
            db.session.add(gate)
            db.session.flush()
        gate_map[code] = gate

    # 3. Admin account
    admin_user = os.getenv("SEED_ADMIN_USERNAME", "admin").strip() or "admin"
    env_admin_pass = os.getenv("SEED_ADMIN_PASSWORD", "").strip()
    admin_pass = env_admin_pass or ("Admin@123" if demo else "ChangeMe@2026!")

    admin = Admin.query.filter_by(username=admin_user).first()
    if not admin:
        admin = Admin(
            username=admin_user,
            full_name="System Administrator",
            role="admin",
            department_id=dept_map["ADMIN"].id,
        )
        admin.set_password(admin_pass, method=pw_method)
        db.session.add(admin)
    elif env_admin_pass:
        # Keep production admin password synced with SEED_ADMIN_PASSWORD on redeploy
        admin.set_password(env_admin_pass, method=pw_method)
        admin.failed_attempts = 0
        admin.locked_until = None

    # 4. Demo Security & Host accounts (only when demo=True)
    if demo:
        demo_users = [
            ("security1", "Guard Rajesh Kumar", "security", "Security@123", None, gate_map["GATE-1"].id),
            ("security2", "Guard Priya Sharma", "security", "Security@123", None, gate_map["GATE-2"].id),
            ("host1", "Prof. Vijay Andhale", "host", "Host@12345", dept_map["CSE"].id, None),
            ("host2", "Dr. Sneha Patil", "host", "Host@12345", dept_map["ECE"].id, None),
            ("host3", "Mr. Amit Deshmukh", "host", "Host@12345", dept_map["ADMIN"].id, None),
        ]
        host1_obj = None
        for uname, fname, role, pwd, did, gid in demo_users:
            u = Admin.query.filter_by(username=uname).first()
            if not u:
                u = Admin(
                    username=uname,
                    full_name=fname,
                    role=role,
                    department_id=did,
                    gate_id=gid,
                )
                u.set_password(pwd, method=pw_method)
                db.session.add(u)
                db.session.flush()
            if uname == "host1":
                host1_obj = u

        # Sample visitors if none exist
        if Visitor.query.count() == 0 and host1_obj:
            ttl = current_app.config.get("QR_TTL_MINUTES", 1440)
            now = utcnow()
            samples = [
                ("Aarav Mehta", "9876543210", "TCS Tech", "Project Viva Demo", "Prof. Vijay Andhale", "approved", "LAN"),
                ("Neha Kulkarni", "9822334455", "Infosys", "Guest Lecture", "Prof. Vijay Andhale", "pending", "LAN"),
                ("Rohan Joshi", "9765432109", "Alumni", "Transcript Collection", "Mr. Amit Deshmukh", "checked_in", "WAN"),
            ]
            for name, mob, comp, purp, meet, st, mode in samples:
                uid = str(uuid.uuid4())
                raw_key = generate_token(12)
                v = Visitor(
                    visitor_uid=uid,
                    transaction_id=f"TXN-{uid[:8].upper()}",
                    name=name,
                    mobile=mob,
                    company=comp,
                    purpose=purp,
                    person_to_meet=meet,
                    department_id=dept_map["CSE"].id,
                    host_id=host1_obj.id,
                    status=st,
                    communication_mode=mode,
                    access_key_hash=hash_token(raw_key),
                    approved_at=now if st in ("approved", "checked_in") else None,
                    checked_in_at=now if st == "checked_in" else None,
                )
                db.session.add(v)
                db.session.flush()
                raw_qr = generate_token(24)
                p = QRPass(
                    visitor_id=v.id,
                    token_hash=hash_token(raw_qr),
                    issued_at=now,
                    expires_at=now + timedelta(minutes=ttl),
                    used_at=now if st == "checked_in" else None,
                )
                db.session.add(p)
                db.session.add(VisitLog(
                    visitor_id=v.id,
                    pass_id=p.id,
                    action="register",
                    mode=mode,
                    client_ip="127.0.0.1",
                    network_type=mode,
                    details=f"Seeded demo visitor ({st})",
                ))

    db.session.commit()
