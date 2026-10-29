"""Utilities for one-time, out-of-band account activation codes."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone


ACTIVATION_CODE_TTL_HOURS = 24


def generate_activation_code() -> tuple[str, str, datetime]:
    """Return a high-entropy code, its SHA-256 digest, and a UTC-naive expiry."""
    code = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ACTIVATION_CODE_TTL_HOURS)).replace(tzinfo=None)
    return code, digest, expires_at


def hash_activation_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
