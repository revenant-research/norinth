"""storage for totp enrollment, recovery codes, and login challenges

secrets are stored encrypted (services/secrets, AAD-bound to the user);
recovery codes and challenge tokens are stored as sha-256 hashes so a
database read never yields anything replayable
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from .raw_events import connect


def hash_opaque(value: str) -> str:
    """storage hash for bearer-style values (recovery codes, challenge tokens)"""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def set_pending_secret(user_ref: str, encrypted_secret: str) -> None:
    """stage a new secret; it only becomes active once a code proves the
    authenticator actually holds it"""
    with connect() as connection:
        connection.execute(
            "UPDATE platform_users SET mfa_pending_secret = ?, updated_at = datetime('now') WHERE user_ref = ?",
            (encrypted_secret, user_ref),
        )


def activate_mfa(user_ref: str) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE platform_users
            SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL,
                mfa_enabled_at = ?, mfa_last_counter = NULL, updated_at = datetime('now')
            WHERE user_ref = ? AND mfa_pending_secret IS NOT NULL
            """,
            (_now(), user_ref),
        )


def clear_mfa(user_ref: str) -> None:
    with connect() as connection:
        connection.execute(
            """
            UPDATE platform_users
            SET mfa_secret = NULL, mfa_pending_secret = NULL, mfa_enabled_at = NULL,
                mfa_last_counter = NULL, updated_at = datetime('now')
            WHERE user_ref = ?
            """,
            (user_ref,),
        )
        connection.execute("DELETE FROM mfa_recovery_codes WHERE user_ref = ?", (user_ref,))
        connection.execute("DELETE FROM mfa_challenges WHERE user_ref = ?", (user_ref,))


def record_used_counter(user_ref: str, counter: int) -> None:
    """persist the accepted totp time step; verify_code refuses anything at or
    below it, which is what makes each code single-use"""
    with connect() as connection:
        connection.execute(
            """
            UPDATE platform_users SET mfa_last_counter = ?
            WHERE user_ref = ? AND (mfa_last_counter IS NULL OR mfa_last_counter < ?)
            """,
            (counter, user_ref, counter),
        )


def replace_recovery_codes(user_ref: str, code_hashes: list[str]) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM mfa_recovery_codes WHERE user_ref = ?", (user_ref,))
        for code_hash in code_hashes:
            connection.execute(
                "INSERT INTO mfa_recovery_codes (user_ref, code_hash, created_at) VALUES (?, ?, ?)",
                (user_ref, code_hash, _now()),
            )


def consume_recovery_code(user_ref: str, code_hash: str) -> bool:
    """burn one unused recovery code; the guarded update makes reuse racing-safe"""
    with connect() as connection:
        cursor = connection.execute(
            "UPDATE mfa_recovery_codes SET used_at = ? WHERE user_ref = ? AND code_hash = ? AND used_at IS NULL",
            (_now(), user_ref, code_hash),
        )
        # rowcount is portable across sqlite3 and the postgres driver here
        return bool(cursor.rowcount)


def count_unused_recovery_codes(user_ref: str) -> int:
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_ref = ? AND used_at IS NULL",
            (user_ref,),
        ).fetchone()
    return int(row["n"])


def create_challenge(token_hash: str, user_ref: str, expires_at: str) -> None:
    with connect() as connection:
        # a fresh password login supersedes any earlier half-finished challenge
        connection.execute("DELETE FROM mfa_challenges WHERE user_ref = ?", (user_ref,))
        connection.execute("DELETE FROM mfa_challenges WHERE expires_at <= ?", (_now(),))
        connection.execute(
            "INSERT INTO mfa_challenges (token, user_ref, attempts, created_at, expires_at) VALUES (?, ?, 0, ?, ?)",
            (token_hash, user_ref, _now(), expires_at),
        )


def load_challenge(token_hash: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM mfa_challenges WHERE token = ? AND expires_at > ?",
            (token_hash, _now()),
        ).fetchone()
    return None if row is None else dict(row)


def register_challenge_attempt(token_hash: str, max_attempts: int) -> None:
    """count a failed code; the challenge burns itself at the cap so a stolen
    challenge token cannot be used to grind codes"""
    with connect() as connection:
        connection.execute("UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token = ?", (token_hash,))
        connection.execute(
            "DELETE FROM mfa_challenges WHERE token = ? AND attempts >= ?",
            (token_hash, max_attempts),
        )


def consume_challenge(token_hash: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM mfa_challenges WHERE token = ?", (token_hash,))
