"""Failed-login throttling to slow credential stuffing / password spraying.

The login endpoint has no external rate limit, so a well-known account (the
default super admin, any provisioned email) could be brute-forced online (audit
H-6). This records failed attempts per email and locks the account for a cooldown
after a threshold, clearing on success.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from .raw_events import connect

LOCKOUT_THRESHOLD = int(os.getenv("NORINTH_LOGIN_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_WINDOW_MINUTES", "15"))
LOCKOUT_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_MINUTES", "15"))


def init_login_attempts() -> None:
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                email TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL DEFAULT 0,
                first_failed_at TEXT,
                locked_until TEXT
            )
            """
        )


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def is_locked(email: str) -> bool:
    with connect() as connection:
        row = connection.execute(
            "SELECT locked_until FROM login_attempts WHERE email = ?", (email,)
        ).fetchone()
    locked_until = _parse(row["locked_until"]) if row else None
    return bool(locked_until and locked_until > _now())


def register_failure(email: str) -> None:
    now = _now()
    with connect() as connection:
        row = connection.execute(
            "SELECT failed_count, first_failed_at FROM login_attempts WHERE email = ?", (email,)
        ).fetchone()
        first_failed = _parse(row["first_failed_at"]) if row else None
        # Reset the counter if the window has elapsed since the first failure.
        if first_failed is None or (now - first_failed) > timedelta(minutes=LOCKOUT_WINDOW_MINUTES):
            failed_count = 1
            first_failed = now
        else:
            failed_count = int(row["failed_count"]) + 1
        locked_until = None
        if failed_count >= LOCKOUT_THRESHOLD:
            locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        connection.execute(
            """
            INSERT INTO login_attempts (email, failed_count, first_failed_at, locked_until)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                failed_count = excluded.failed_count,
                first_failed_at = excluded.first_failed_at,
                locked_until = excluded.locked_until
            """,
            (
                email,
                failed_count,
                first_failed.isoformat(),
                locked_until.isoformat() if locked_until else None,
            ),
        )


def clear_attempts(email: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
