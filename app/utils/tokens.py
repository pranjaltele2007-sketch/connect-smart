"""Cryptographic token generation and HMAC-SHA256 hashing utilities."""
import hashlib
import hmac
import secrets
from flask import current_app


def generate_token(nbytes: int = 24) -> str:
    """Return a URL-safe cryptographically random token."""
    return secrets.token_urlsafe(nbytes)


def get_pepper() -> str:
    pepper = current_app.config.get("QR_HASH_PEPPER") or current_app.config.get("SECRET_KEY")
    if not pepper:
        raise RuntimeError("SECRET_KEY or QR_HASH_PEPPER must be configured.")
    return str(pepper)


def hash_token(raw_token: str, pepper: str | None = None) -> str:
    """Compute keyed HMAC-SHA256 hex digest of a raw token. Only hashes are stored in DB."""
    key = (pepper if pepper is not None else get_pepper()).encode("utf-8")
    return hmac.new(key, raw_token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_token_hash(raw_token: str, stored_hash: str, pepper: str | None = None) -> bool:
    """Constant-time verification of a raw token against a stored HMAC-SHA256 hash."""
    computed = hash_token(raw_token, pepper=pepper)
    return hmac.compare_digest(computed, stored_hash)
