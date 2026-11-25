"""Network discovery, IP classification (LAN vs WAN), and input helpers."""
import ipaddress
import re
import socket
from flask import current_app, Request


def get_lan_ips() -> list[str]:
    """Discover active non-loopback IPv4 LAN addresses on this machine."""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except OSError:
        pass

    # Fallback: connect UDP socket to discover primary outbound interface
    if not ips:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if not ip.startswith("127."):
                    ips.append(ip)
        except OSError:
            pass
    return ips


def get_client_ip(req: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For only when BEHIND_PROXY=True."""
    if current_app.config.get("BEHIND_PROXY"):
        forwarded = req.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = req.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
    return req.remote_addr or "127.0.0.1"


def classify_network(ip_str: str) -> str:
    """Classify an IP address as 'LAN' (private/loopback/link-local) or 'WAN' (public)."""
    if not ip_str:
        return "LAN"
    try:
        # Handle IPv6-mapped IPv4 like ::ffff:192.168.1.5
        clean = ip_str.split("%")[0].strip()
        addr = ipaddress.ip_address(clean)
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return "LAN"
        return "WAN"
    except ValueError:
        return "LAN"


MOBILE_RE = re.compile(r"^\+?[0-9\-\s]{7,18}$")


def is_valid_mobile(mobile: str) -> bool:
    return bool(mobile and MOBILE_RE.match(mobile.strip()))


def clean_str(val: str | None, max_len: int = 200) -> str:
    if not val:
        return ""
    return " ".join(str(val).strip().split())[:max_len]
