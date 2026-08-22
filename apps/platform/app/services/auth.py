from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta

from app.storage.workflow import (
    delete_session,
    delete_sessions_for_user,
    insert_session,
    load_session,
    purge_expired_sessions,
)

# Password hashing parameters. PBKDF2-HMAC-SHA256 is part of the standard
# library, which keeps the open/closed dependency boundary clean (no external
# crypto dependency) while remaining a defensible KDF for an internal app.
_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = 240_000
_SALT_BYTES = 16

SESSION_TTL_HOURS = int(os.getenv("NORINTH_SESSION_TTL_HOURS", "12"))


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(_PBKDF2_ALGORITHM, password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_{_PBKDF2_ALGORITHM}${_PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, iterations, salt_hex, expected_hex = stored.split("$")
    except ValueError:
        return False
    if not scheme.startswith("pbkdf2_"):
        return False
    algorithm = scheme.removeprefix("pbkdf2_")
    derived = hashlib.pbkdf2_hmac(algorithm, password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(derived.hex(), expected_hex)


def _hash_token(token: str) -> str:
    """Hash a session token for storage.

    Session tokens are high-entropy bearer secrets; storing only their SHA-256
    means a database read (or backup leak) never yields a usable, replayable
    token (audit H-7).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_ref: str) -> str:
    purge_expired_sessions()
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now(UTC) + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    insert_session(_hash_token(token), user_ref, expires_at)
    return token


def resolve_session(token: str | None) -> str | None:
    if not token:
        return None
    session = load_session(_hash_token(token))
    return None if session is None else session["user_ref"]


def end_session(token: str | None) -> None:
    if token:
        delete_session(_hash_token(token))


def end_all_sessions(user_ref: str) -> None:
    """Revoke every active session for a user (e.g. after a password change)."""
    delete_sessions_for_user(user_ref)
