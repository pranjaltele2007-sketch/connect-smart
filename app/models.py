"""Database models for SmartConnect Visitor Management System."""
from datetime import datetime, timezone
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    floor = db.Column(db.String(40), default="Ground Floor")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class Gate(db.Model):
    __tablename__ = "gates"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    location = db.Column(db.String(120), default="Main Campus")
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class Admin(db.Model):
    """Staff user model supporting roles: admin, host, security."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="host")  # admin | host | security
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"), nullable=True)
    gate_id = db.Column(db.Integer, db.ForeignKey("gates.id"), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    department = db.relationship("Department", lazy="joined")
    gate = db.relationship("Gate", lazy="joined")

    def set_password(self, password: str, method: str = "pbkdf2:sha256:150000") -> None:
        self.password_hash = generate_password_hash(password, method=method)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())


class Visitor(db.Model):
    __tablename__ = "visitors"

    id = db.Column(db.Integer, primary_key=True)
    visitor_uid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    transaction_id = db.Column(db.String(64), unique=True, nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(20), nullable=False, index=True)
    email = db.Column(db.String(120), default="")
    company = db.Column(db.String(120), default="")
    purpose = db.Column(db.String(200), nullable=False)
    person_to_meet = db.Column(db.String(120), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    communication_mode = db.Column(db.String(20), nullable=False, default="LAN")  # LAN | WAN | OFFLINE_QR
    access_key_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    checked_in_at = db.Column(db.DateTime, nullable=True)
    checked_out_at = db.Column(db.DateTime, nullable=True)
    imported_at = db.Column(db.DateTime, nullable=True)

    department = db.relationship("Department", lazy="joined")
    host = db.relationship("Admin", foreign_keys=[host_id], lazy="joined")
    passes = db.relationship("QRPass", back_populates="visitor", cascade="all, delete-orphan")


class QRPass(db.Model):
    __tablename__ = "qr_passes"

    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey("visitors.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    issued_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    visitor = db.relationship("Visitor", back_populates="passes")

    def is_expired(self) -> bool:
        return utcnow() > self.expires_at


class VisitLog(db.Model):
    __tablename__ = "visit_logs"

    id = db.Column(db.Integer, primary_key=True)
    visitor_id = db.Column(db.Integer, db.ForeignKey("visitors.id"), nullable=True, index=True)
    pass_id = db.Column(db.Integer, db.ForeignKey("qr_passes.id"), nullable=True)
    gate_id = db.Column(db.Integer, db.ForeignKey("gates.id"), nullable=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(32), nullable=False, index=True)
    mode = db.Column(db.String(20), nullable=False, default="LAN")
    client_ip = db.Column(db.String(64), default="")
    network_type = db.Column(db.String(10), default="LAN")
    details = db.Column(db.String(300), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    visitor = db.relationship("Visitor", lazy="joined")
    gate = db.relationship("Gate", lazy="joined")
    actor = db.relationship("Admin", lazy="joined")


class CommLog(db.Model):
    """Measured network telemetry log for /admin/network."""
    __tablename__ = "comm_logs"

    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(200), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    latency_ms = db.Column(db.Float, nullable=False)
    client_ip = db.Column(db.String(64), default="")
    network_type = db.Column(db.String(10), default="LAN")  # LAN | WAN
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
