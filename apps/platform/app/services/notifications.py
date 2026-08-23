"""notification service: compose events, resolve recipients, deliver

``emit`` is called from request handlers and storage routines with the caller's
connection and only writes outbox rows. ``deliver_pending`` runs in the
background worker (``start_worker``) and in tests; it sends email over smtp and
posts signed webhooks.

env config:
  NORINTH_SMTP_HOST, NORINTH_SMTP_PORT (587), NORINTH_SMTP_USER,
  NORINTH_SMTP_PASSWORD, NORINTH_SMTP_FROM, NORINTH_SMTP_STARTTLS (1)
  NORINTH_PUBLIC_BASE_URL -- builds links in emails
  NORINTH_NOTIFICATIONS_WORKER=0 disables the worker thread (tests).
without smtp configured, email rows are recorded with status
``skipped_no_smtp`` so an admin can see what would have been sent
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

from app.services.net_guard import validate_external_url
from app.storage import notifications as store
from app.storage.raw_events import connect

log = logging.getLogger("norinth.notifications")

_ROLE_RECIPIENT_SQL = """
SELECT DISTINCT platform_users.email
FROM role_assignments
JOIN platform_users ON platform_users.user_ref = role_assignments.user_ref
WHERE role_assignments.role = ?
  AND role_assignments.status = 'active'
  AND platform_users.status = 'active'
  AND platform_users.email IS NOT NULL
  AND (role_assignments.tenant_id IS NULL OR role_assignments.tenant_id = ?)
"""


def smtp_configured() -> bool:
    return bool(os.getenv("NORINTH_SMTP_HOST"))


def public_base_url() -> str:
    return (os.getenv("NORINTH_PUBLIC_BASE_URL") or "http://localhost:8001").rstrip("/")


def _user_email(connection, user_ref: str) -> str | None:
    row = connection.execute("SELECT email, status FROM platform_users WHERE user_ref = ?", (user_ref,)).fetchone()
    if row is None or row["status"] != "active":
        return None
    return row["email"]


def emit(
    connection,
    *,
    tenant_id: str | None,
    event_type: str,
    subject: str,
    text: str,
    data: dict[str, Any] | None = None,
    to_users: list[str] | None = None,
    to_roles: list[str] | None = None,
    link: str | None = None,
) -> int:
    """write outbox rows for an event, returns rows written"""
    recipients: set[str] = set()
    for user_ref in to_users or []:
        email = _user_email(connection, user_ref)
        if email:
            recipients.add(email.lower())
    for role in to_roles or []:
        for row in connection.execute(_ROLE_RECIPIENT_SQL, (role, tenant_id)).fetchall():
            recipients.add(row["email"].lower())
    body = {
        "type": event_type,
        "tenant_id": tenant_id,
        "occurred_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": subject,
        "text": text,
        "link": link,
        "data": data or {},
    }
    written = 0
    email_status = "pending" if smtp_configured() else "skipped_no_smtp"
    for email in sorted(recipients):
        store.enqueue(connection, tenant_id=tenant_id, channel="email", event_type=event_type, target=email, subject=subject, payload=body, status=email_status)
        written += 1
    if tenant_id:
        for hook in store.active_webhooks_for(connection, tenant_id, event_type):
            store.enqueue(connection, tenant_id=tenant_id, channel="webhook", event_type=event_type, target=hook["webhook_id"], subject=subject, payload=body)
            written += 1
    return written


# --- delivery ---------------------------------------------------------------------


def _send_email(to: str, subject: str, payload: dict[str, Any]) -> None:
    host = os.environ["NORINTH_SMTP_HOST"]
    port = int(os.getenv("NORINTH_SMTP_PORT", "587"))
    user = os.getenv("NORINTH_SMTP_USER")
    password = os.getenv("NORINTH_SMTP_PASSWORD")
    sender = os.getenv("NORINTH_SMTP_FROM") or (user or "norinth@localhost")
    starttls = os.getenv("NORINTH_SMTP_STARTTLS", "1").lower() not in {"0", "false", "no"}
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    text = payload.get("text") or ""
    if payload.get("link"):
        text += f"\n\n{payload['link']}\n"
    text += "\n-- \nSent by Norinth. You are receiving this because of your role in your organization's AI governance."
    msg.set_content(text)
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if starttls:
            # starttls with no context skips cert verification (mitm-able); pass a
            # verifying context. NORINTH_SMTP_INSECURE=1 opts out for a self-signed
            # internal relay
            if os.getenv("NORINTH_SMTP_INSECURE", "0").lower() in {"1", "true", "yes"}:
                context = ssl._create_unverified_context()
            else:
                context = ssl.create_default_context()
            smtp.starttls(context=context)
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)


def _slack_payload(payload: dict[str, Any]) -> dict[str, Any]:
    text = f"*{payload.get('subject')}*\n{payload.get('text')}"
    if payload.get("link"):
        text += f"\n<{payload['link']}|Open in Norinth>"
    return {"text": text}


def _post_webhook(hook: dict[str, Any], payload: dict[str, Any]) -> None:
    body_obj = _slack_payload(payload) if hook.get("format") == "slack" else payload
    body = json.dumps(body_obj, sort_keys=True).encode("utf-8")
    secret = store.webhook_secret(hook)
    # sign timestamp + body (stripe-style) so a captured request can't be
    # replayed: receiver rejects an old X-Norinth-Timestamp and recomputes
    # HMAC(secret, "<timestamp>." + body). the per-delivery id lets it dedupe
    timestamp = str(int(datetime.now(UTC).timestamp()))
    signed = f"{timestamp}.".encode() + body
    signature = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    delivery_id = uuid.uuid4().hex
    validate_external_url(hook["url"])
    req = urllib.request.Request(
        hook["url"],
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "norinth-webhook/1",
            "X-Norinth-Event": payload.get("type", ""),
            "X-Norinth-Timestamp": timestamp,
            "X-Norinth-Signature": f"t={timestamp},v1={signature}",
            "X-Norinth-Delivery": delivery_id,
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - operator-configured URL
        if resp.status >= 300:
            raise RuntimeError(f"webhook returned {resp.status}")


def deliver_one(row: dict[str, Any]) -> tuple[bool, str | None]:
    payload = json.loads(row["payload"])
    try:
        if row["channel"] == "email":
            _send_email(row["target"], row["subject"] or payload.get("subject") or "Norinth", payload)
        elif row["channel"] == "webhook":
            hook = None
            with connect() as connection:
                r = connection.execute("SELECT * FROM webhooks WHERE webhook_id = ?", (row["target"],)).fetchone()
                hook = None if r is None else dict(r)
            if hook is None or hook.get("status") != "active":
                return False, "webhook no longer exists or is disabled"
            try:
                _post_webhook(hook, payload)
                store.record_webhook_delivery(hook["webhook_id"], "ok")
            except urllib.error.HTTPError as error:
                store.record_webhook_delivery(hook["webhook_id"], f"http {error.code}")
                raise
            except Exception as error:
                store.record_webhook_delivery(hook["webhook_id"], f"error: {error}"[:80])
                raise
        else:
            return False, f"unknown channel {row['channel']}"
        return True, None
    except Exception as error:  # noqa: BLE001 - recorded, retried
        return False, f"{type(error).__name__}: {error}"


_WORKER_ID = f"{os.uname().nodename}:{os.getpid()}"


def deliver_pending(limit: int = 50) -> dict[str, int]:
    sent = failed = 0
    for row in store.claim_pending(limit, worker_id=_WORKER_ID):
        ok, error = deliver_one(row)
        attempts = int(row["attempts"]) + 1
        store.mark_result(int(row["id"]), ok=ok, error=error, attempts=attempts)
        if ok:
            sent += 1
        else:
            failed += 1
            log.warning("notification %s via %s failed (attempt %s): %s", row["event_type"], row["channel"], attempts, error)
    return {"sent": sent, "failed": failed}


_worker_started = False


def start_worker(interval_seconds: float = 5.0) -> None:
    """background delivery loop, idempotent; disabled with NORINTH_NOTIFICATIONS_WORKER=0"""
    global _worker_started
    if _worker_started or os.getenv("NORINTH_NOTIFICATIONS_WORKER", "1").lower() in {"0", "false", "no"}:
        return
    _worker_started = True

    def loop() -> None:
        while True:
            try:
                deliver_pending()
            except Exception:  # noqa: BLE001
                log.exception("notification worker iteration failed")
            time.sleep(interval_seconds)

    threading.Thread(target=loop, name="norinth-notifications", daemon=True).start()
