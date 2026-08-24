"""failed-login throttling, per account and per source ip

per-account lockout alone misses two cases: deliberate targeted lockout, and
password spraying across many accounts from one source. the ip threshold is
higher so a shared office nat isn't blocked by a few typos. subjects are
namespaced strings ("email:<addr>", "ip:<addr>") in one table
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from .raw_events import connect

# per-account policy
LOCKOUT_THRESHOLD = int(os.getenv("NORINTH_LOGIN_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_WINDOW_MINUTES", "15"))
LOCKOUT_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_MINUTES", "15"))
# per-source-ip policy, higher threshold since many users may share an egress ip
IP_THRESHOLD = int(os.getenv("NORINTH_LOGIN_IP_THRESHOLD", "50"))
IP_WINDOW_MINUTES = int(os.getenv("NORINTH_LOGIN_IP_WINDOW_MINUTES", "15"))
IP_LOCKOUT_MINUTES = int(os.getenv("NORINTH_LOGIN_IP_LOCKOUT_MINUTES", "15"))


def ensure_login_throttle_table(connection) -> None:
    """login_throttle schema, idempotent"""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS login_throttle (
            subject TEXT PRIMARY KEY,
            failed_count INTEGER NOT NULL DEFAULT 0,
            first_failed_at TEXT,
            locked_until TEXT
        )
        """
    )


def init_login_attempts() -> None:
    """kept for the baseline migration; creating it here too keeps fresh
    databases and tests consistent"""
    with connect() as connection:
        ensure_login_throttle_table(connection)


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _policy(subject: str) -> tuple[int, int, int]:
    if subject.startswith("ip:"):
        return IP_THRESHOLD, IP_WINDOW_MINUTES, IP_LOCKOUT_MINUTES
    return LOCKOUT_THRESHOLD, LOCKOUT_WINDOW_MINUTES, LOCKOUT_MINUTES


def is_locked(subject: str) -> bool:
    with connect() as connection:
        row = connection.execute("SELECT locked_until FROM login_throttle WHERE subject = ?", (subject,)).fetchone()
    locked_until = _parse(row["locked_until"]) if row else None
    return bool(locked_until and locked_until > _now())


def register_failure(subject: str) -> None:
    """record one failed attempt, atomic so concurrent failures aren't lost

    the increment is a single upsert; a separate guarded update first resets an
    expired, unlocked window. both compare iso timestamps, which sort
    lexicographically since every value is utc in the same format
    """
    threshold, window_minutes, lockout_minutes = _policy(subject)
    now = _now()
    now_iso = now.isoformat()
    window_cutoff = (now - timedelta(minutes=window_minutes)).isoformat()
    locked_iso = (now + timedelta(minutes=lockout_minutes)).isoformat()
    with connect() as connection:
        # reset an expired window, but only when not currently locked, so a
        # reset can't lift an active lockout
        connection.execute(
            """
            UPDATE login_throttle
            SET failed_count = 0, first_failed_at = ?, locked_until = NULL
            WHERE subject = ?
              AND first_failed_at IS NOT NULL
              AND first_failed_at < ?
              AND (locked_until IS NULL OR locked_until < ?)
            """,
            (now_iso, subject, window_cutoff, now_iso),
        )
        # atomic increment: the db serializes writers on the row, so no
        # increment is lost; locked_until is set once the count hits the threshold
        connection.execute(
            """
            INSERT INTO login_throttle (subject, failed_count, first_failed_at, locked_until)
            VALUES (?, 1, ?, NULL)
            ON CONFLICT(subject) DO UPDATE SET
                failed_count = login_throttle.failed_count + 1,
                first_failed_at = COALESCE(login_throttle.first_failed_at, ?),
                locked_until = CASE
                    WHEN login_throttle.failed_count + 1 >= ? THEN ?
                    ELSE login_throttle.locked_until
                END
            """,
            (subject, now_iso, now_iso, threshold, locked_iso),
        )


def clear_attempts(subject: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM login_throttle WHERE subject = ?", (subject,))


# wrappers used by the login route
def email_subject(email: str) -> str:
    return f"email:{email.strip().lower()}"


def ip_subject(ip: str | None) -> str:
    return f"ip:{ip or 'unknown'}"
