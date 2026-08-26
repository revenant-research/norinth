"""notification outbox, webhooks and invites

no request path talks to smtp or a webhook url: events are written to
notification_outbox in the caller's transaction and a background worker delivers
them with retries, so a slow mail server can't slow governance actions and
nothing is lost on failure. every row keeps its status and last error
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import Any

from app.services import secrets as secret_store

from .db import is_postgres
from .raw_events import connect

WEBHOOK_EVENTS = (
    "user.invited",
    "review.assigned",
    "review.overdue",
    "review.escalated",
    "gate.approved",
    "gate.rejected",
    "incident.opened",
    "incident.closed",
    "test",
)
INVITE_TTL_DAYS = 7


def ensure_notification_tables(connection) -> None:
    """outbox, webhooks, invites schema, idempotent"""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            channel TEXT NOT NULL,
            event_type TEXT NOT NULL,
            target TEXT NOT NULL,
            subject TEXT,
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TEXT NOT NULL,
            sent_at TEXT,
            next_attempt_at TEXT,
            claimed_by TEXT,
            claimed_at TEXT
        )
        """
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status ON notification_outbox (status, next_attempt_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_outbox_tenant ON notification_outbox (tenant_id, id)")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            webhook_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            secret TEXT NOT NULL,
            events TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'json',
            status TEXT NOT NULL DEFAULT 'active',
            created_by TEXT,
            created_at TEXT NOT NULL,
            last_delivery_at TEXT,
            last_status TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS invites (
            token_hash TEXT PRIMARY KEY,
            user_ref TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT
        )
        """
    )


# --- outbox -------------------------------------------------------------------------


def enqueue(
    connection,
    *,
    tenant_id: str | None,
    channel: str,
    event_type: str,
    target: str,
    subject: str | None,
    payload: dict[str, Any],
    status: str = "pending",
) -> None:
    connection.execute(
        """
        INSERT INTO notification_outbox (tenant_id, channel, event_type, target, subject, payload, status, created_at, next_attempt_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """,
        (tenant_id, channel, event_type, target, subject, json.dumps(payload, sort_keys=True), status),
    )


STALE_CLAIM_MINUTES = 10


def ensure_claim_columns(connection) -> None:
    """delivery claim columns, idempotent"""
    for statement in (
        "ALTER TABLE notification_outbox ADD COLUMN claimed_by TEXT",
        "ALTER TABLE notification_outbox ADD COLUMN claimed_at TEXT",
    ):
        try:
            connection.execute(statement)
        except Exception:  # noqa: BLE001 - column already exists
            pass


def claim_pending(limit: int = 50, *, worker_id: str) -> list[dict[str, Any]]:
    """atomically claim up to limit due rows for this worker

    each replica runs a delivery worker; the claim is one update flipping status
    to 'delivering' for still-'pending' rows, so two replicas can't both deliver
    a row. rows claimed by a dead worker return to 'pending' after
    STALE_CLAIM_MINUTES
    """
    with connect() as connection:
        # anchor the reference time to the DATABASE server clock, not this
        # process's clock. next_attempt_at is written with SQL datetime('now')
        # (the server clock), so comparing it against a Python-computed now would
        # be wrong by whatever the app-host and db-server clocks differ by, and a
        # worker could skip due rows or reset live claims. reading the server time
        # here keeps every outbox timestamp on one clock
        now = connection.execute("SELECT datetime('now') AS now").fetchone()["now"]
        now_dt = datetime.strptime(now, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        stale_before = (now_dt - timedelta(minutes=STALE_CLAIM_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        connection.execute(
            "UPDATE notification_outbox SET status = 'pending', claimed_by = NULL, claimed_at = NULL "
            "WHERE status = 'delivering' AND claimed_at <= ?",
            (stale_before,),
        )
        # on postgres, FOR UPDATE SKIP LOCKED makes this a work queue: a selector
        # skips rows another replica locked, so two workers never select the same
        # batch. sqlite serializes writers and doesn't support the clause
        skip_locked = " FOR UPDATE SKIP LOCKED" if is_postgres() else ""
        connection.execute(
            f"""
            UPDATE notification_outbox SET status = 'delivering', claimed_by = ?, claimed_at = ?
            WHERE id IN (
                SELECT id FROM notification_outbox
                WHERE status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY id LIMIT ?{skip_locked}
            )
            """,
            (worker_id, now, now, limit),
        )
        rows = connection.execute(
            "SELECT * FROM notification_outbox WHERE status = 'delivering' AND claimed_by = ? ORDER BY id",
            (worker_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_result(row_id: int, *, ok: bool, error: str | None, attempts: int, max_attempts: int = 6) -> None:
    with connect() as connection:
        if ok:
            connection.execute(
                "UPDATE notification_outbox SET status = 'sent', attempts = ?, last_error = NULL, sent_at = datetime('now'), claimed_by = NULL, claimed_at = NULL WHERE id = ?",
                (attempts, row_id),
            )
            return
        if attempts >= max_attempts:
            connection.execute(
                "UPDATE notification_outbox SET status = 'failed', attempts = ?, last_error = ?, claimed_by = NULL, claimed_at = NULL WHERE id = ?",
                (attempts, (error or "")[:500], row_id),
            )
            return
        backoff = timedelta(minutes=min(60, 2 ** attempts))
        next_at = (datetime.now(UTC) + backoff).strftime("%Y-%m-%d %H:%M:%S")
        connection.execute(
            "UPDATE notification_outbox SET status = 'pending', attempts = ?, last_error = ?, next_attempt_at = ?, claimed_by = NULL, claimed_at = NULL WHERE id = ?",
            (attempts, (error or "")[:500], next_at, row_id),
        )


def list_outbox(tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            "SELECT id, channel, event_type, target, subject, status, attempts, last_error, created_at, sent_at FROM notification_outbox WHERE tenant_id = ? ORDER BY id DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


# --- webhooks -----------------------------------------------------------------------


def mask_url(url: str) -> str:
    """hide a webhook url's path; a slack incoming-webhook carries its auth
    token there, so exposing it leaks a bearer secret. keep scheme and host only"""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "[redacted-url]"
    if not parsed.scheme or not parsed.netloc:
        return "[redacted-url]"
    suffix = "/…" if parsed.path not in ("", "/") or parsed.query else ""
    return f"{parsed.scheme}://{parsed.netloc}{suffix}"


def _public_webhook(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in row.items() if k != "secret"}
    # never expose the full url (its path may be a bearer secret), host only
    if out.get("url"):
        out["url"] = mask_url(out["url"])
    out["events"] = json.loads(row["events"])
    return out


def create_webhook(tenant_id: str, *, name: str, url: str, events: list[str], fmt: str, created_by: str | None) -> tuple[str, dict[str, Any]]:
    """returns (signing secret shown once, public record)"""
    webhook_id = "whk_" + secrets.token_urlsafe(9)
    secret = "whs_" + secrets.token_urlsafe(24)
    # always encrypt, fail-closed: encrypt() raises without a key rather than
    # storing the signing secret in plaintext
    stored = secret_store.encrypt(secret, associated_data=f"webhook:{tenant_id}:{webhook_id}")
    with connect() as connection:
        connection.execute(
            "INSERT INTO webhooks (webhook_id, tenant_id, name, url, secret, events, format, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))",
            (webhook_id, tenant_id, name, url, stored, json.dumps(sorted(events)), fmt, created_by),
        )
        row = connection.execute("SELECT * FROM webhooks WHERE webhook_id = ?", (webhook_id,)).fetchone()
    return secret, _public_webhook(dict(row))


def list_webhooks(tenant_id: str) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute("SELECT * FROM webhooks WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,)).fetchall()
    return [_public_webhook(dict(r)) for r in rows]


def active_webhooks_for(connection, tenant_id: str, event_type: str) -> list[dict[str, Any]]:
    rows = connection.execute("SELECT * FROM webhooks WHERE tenant_id = ? AND status = 'active'", (tenant_id,)).fetchall()
    out = []
    for row in rows:
        events = json.loads(row["events"])
        if event_type in events or "*" in events:
            out.append(dict(row))
    return out


def webhook_secret(row: dict[str, Any]) -> str:
    stored = row["secret"]
    if secret_store.is_encrypted(stored):
        return secret_store.decrypt(stored, associated_data=f"webhook:{row['tenant_id']}:{row['webhook_id']}")
    return stored


def load_webhook(webhook_id: str, tenant_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM webhooks WHERE webhook_id = ? AND tenant_id = ?", (webhook_id, tenant_id)).fetchone()
    return None if row is None else dict(row)


def delete_webhook(webhook_id: str, tenant_id: str) -> bool:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM webhooks WHERE webhook_id = ? AND tenant_id = ?", (webhook_id, tenant_id))
        return bool(cursor.rowcount)


def record_webhook_delivery(webhook_id: str, status: str) -> None:
    with connect() as connection:
        connection.execute("UPDATE webhooks SET last_delivery_at = datetime('now'), last_status = ? WHERE webhook_id = ?", (status, webhook_id))


# --- invites ------------------------------------------------------------------------


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_invite(user_ref: str, tenant_id: str, created_by: str | None) -> str:
    token = "inv_" + secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    with connect() as connection:
        connection.execute("DELETE FROM invites WHERE user_ref = ? AND used_at IS NULL", (user_ref,))
        connection.execute(
            "INSERT INTO invites (token_hash, user_ref, tenant_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (_hash(token), user_ref, tenant_id, created_by, now.isoformat(), (now + timedelta(days=INVITE_TTL_DAYS)).isoformat()),
        )
    return token


def peek_invite(token: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM invites WHERE token_hash = ?", (_hash(token),)).fetchone()
    if row is None or row["used_at"] is not None:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
        return None
    return dict(row)


def consume_invite(token: str) -> dict[str, Any] | None:
    invite = peek_invite(token)
    if invite is None:
        return None
    with connect() as connection:
        cursor = connection.execute(
            "UPDATE invites SET used_at = ? WHERE token_hash = ? AND used_at IS NULL", (datetime.now(UTC).isoformat(), _hash(token))
        )
        if not cursor.rowcount:
            return None
    return invite
