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

# pbkdf2-hmac-sha256 is stdlib, no external crypto dep. iteration count meets
# owasp 2023 guidance (600k), env-tunable so tests can lower it; weaker hashes are
# upgraded on the next successful login
_PBKDF2_ALGORITHM = "sha256"
_PBKDF2_ITERATIONS = int(os.getenv("NORINTH_PBKDF2_ITERATIONS", "600000"))
_SALT_BYTES = 16
# a hash string names its own kdf; allowlist so a tampered db row can't make the
# verifier run a weak or attacker-chosen digest
_ALLOWED_ALGORITHMS = {"sha256", "sha512"}

SESSION_TTL_HOURS = int(os.getenv("NORINTH_SESSION_TTL_HOURS", "12"))

# one password floor for every place a password is set (signup, invite, change,
# admin-set). without a single value the change-password path allowed 8 while
# signup required 12, so the strong floor was bypassable by changing the password
MIN_PASSWORD_LENGTH = 12


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
    if algorithm not in _ALLOWED_ALGORITHMS:
        return False
    try:
        rounds = int(iterations)
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac(algorithm, password.encode("utf-8"), bytes.fromhex(salt_hex), rounds)
    return hmac.compare_digest(derived.hex(), expected_hex)


def needs_rehash(stored: str | None) -> bool:
    """true when a stored hash is weaker than current params (diff algo or fewer iterations)"""
    if not stored:
        return True
    try:
        scheme, iterations, _, _ = stored.split("$")
    except ValueError:
        return True
    if not scheme.startswith("pbkdf2_"):
        return True
    algorithm = scheme.removeprefix("pbkdf2_")
    try:
        return algorithm != _PBKDF2_ALGORITHM or int(iterations) < _PBKDF2_ITERATIONS
    except ValueError:
        return True


def _hash_token(token: str) -> str:
    """hash a session token for storage

    tokens are bearer secrets; storing only the sha-256 means a db read or backup
    leak never yields a replayable token
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
    """revoke every active session for a user, e.g. after a password change"""
    delete_sessions_for_user(user_ref)
