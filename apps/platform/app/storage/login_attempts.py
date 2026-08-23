"""Failed-login throttling, per account AND per source IP.

Per-account lockout alone (audit H-6) has two gaps: an attacker can lock a
victim out on purpose (targeted-lockout DoS), and spraying one password across
many accounts from one source never trips a per-account counter. Throttling the
source IP closes both. Thresholds are separate: the IP threshold is higher so a
shared office NAT is not blocked by a handful of typos.

Subjects are namespaced strings ("email:<addr>", "ip:<addr>") in one table.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from .raw_events import connect

# Per-account policy.
LOCKOUT_THRESHOLD = int(os.getenv("NORINTH_LOGIN_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_WINDOW_MINUTES", "15"))
LOCKOUT_MINUTES = int(os.getenv("NORINTH_LOGIN_LOCKOUT_MINUTES", "15"))
# Per-source-IP policy (higher threshold: many users may share an egress IP).
IP_THRESHOLD = int(os.getenv("NORINTH_LOGIN_IP_THRESHOLD", "50"))
IP_WINDOW_MINUTES = int(os.getenv("NORINTH_LOGIN_IP_WINDOW_MINUTES", "15"))
IP_LOCKOUT_MINUTES = int(os.getenv("NORINTH_LOGIN_IP_LOCKOUT_MINUTES", "15"))


def ensure_login_throttle_table(connection) -> None:
    """Schema for migration 4 (idempotent)."""
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
    """Kept for the baseline migration; the table now lives in migration 4 but
    creating it here too keeps fresh databases and tests consistent."""
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
    threshold, window_minutes, lockout_minutes = _policy(subject)
    now = _now()
    with connect() as connection:
        row = connection.execute(
            "SELECT failed_count, first_failed_at FROM login_throttle WHERE subject = ?", (subject,)
        ).fetchone()
        first_failed = _parse(row["first_failed_at"]) if row else None
        if first_failed is None or (now - first_failed) > timedelta(minutes=window_minutes):
            failed_count = 1
            first_failed = now
        else:
            failed_count = int(row["failed_count"]) + 1
        locked_until = now + timedelta(minutes=lockout_minutes) if failed_count >= threshold else None
        connection.execute(
            """
            INSERT INTO login_throttle (subject, failed_count, first_failed_at, locked_until)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(subject) DO UPDATE SET
                failed_count = excluded.failed_count,
                first_failed_at = excluded.first_failed_at,
                locked_until = excluded.locked_until
            """,
            (subject, failed_count, first_failed.isoformat(), locked_until.isoformat() if locked_until else None),
        )


def clear_attempts(subject: str) -> None:
    with connect() as connection:
        connection.execute("DELETE FROM login_throttle WHERE subject = ?", (subject,))


# Convenience wrappers used by the login route.
def email_subject(email: str) -> str:
    return f"email:{email.strip().lower()}"


def ip_subject(ip: str | None) -> str:
    return f"ip:{ip or 'unknown'}"
