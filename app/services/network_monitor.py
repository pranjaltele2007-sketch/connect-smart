"""Real-time network telemetry tracker (LAN vs WAN, latency, status codes, WS clients)."""
from collections import deque
from threading import Lock
import time

_lock = Lock()
_recent_requests = deque(maxlen=150)
_active_ws_sids: set[str] = set()
_counters = {
    "total_requests": 0,
    "lan_requests": 0,
    "wan_requests": 0,
    "status_2xx": 0,
    "status_3xx": 0,
    "status_4xx": 0,
    "status_5xx": 0,
    "started_at": time.time(),
}


def record_request(method: str, path: str, status_code: int, latency_ms: float, client_ip: str, network_type: str) -> None:
    with _lock:
        _counters["total_requests"] += 1
        if network_type == "WAN":
            _counters["wan_requests"] += 1
        else:
            _counters["lan_requests"] += 1

        if 200 <= status_code < 300:
            _counters["status_2xx"] += 1
        elif 300 <= status_code < 400:
            _counters["status_3xx"] += 1
        elif 400 <= status_code < 500:
            _counters["status_4xx"] += 1
        elif status_code >= 500:
            _counters["status_5xx"] += 1

        _recent_requests.appendleft({
            "method": method,
            "path": path,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "client_ip": client_ip,
            "network_type": network_type,
            "ts": time.strftime("%H:%M:%S"),
        })


def ws_connect(sid: str) -> int:
    with _lock:
        _active_ws_sids.add(sid)
        return len(_active_ws_sids)


def ws_disconnect(sid: str) -> int:
    with _lock:
        _active_ws_sids.discard(sid)
        return len(_active_ws_sids)


def get_snapshot() -> dict:
    with _lock:
        reqs = list(_recent_requests)
        latencies = [r["latency_ms"] for r in reqs]
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        p95_lat = round(sorted(latencies)[int(0.95 * len(latencies))], 2) if len(latencies) >= 2 else avg_lat
        return {
            **_counters,
            "uptime_seconds": int(time.time() - _counters["started_at"]),
            "ws_clients": len(_active_ws_sids),
            "avg_latency_ms": avg_lat,
            "p95_latency_ms": p95_lat,
            "recent": reqs[:40],
        }
