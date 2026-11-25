"""Flask-SocketIO real-time event handlers with session role verification."""
from flask import request, session
from flask_socketio import join_room

from app.extensions import socketio
from app.models import Admin
from app.services.network_monitor import ws_connect, ws_disconnect


@socketio.on("connect")
def handle_connect():
    count = ws_connect(request.sid)
    uid = session.get("user_id")
    if uid:
        user = Admin.query.get(uid)
        if user and user.is_active:
            join_room(f"role:{user.role}")
            join_room(f"user:{user.id}")
    socketio.emit("network:ws_clients", {"ws_clients": count})


@socketio.on("disconnect")
def handle_disconnect():
    count = ws_disconnect(request.sid)
    socketio.emit("network:ws_clients", {"ws_clients": count})
