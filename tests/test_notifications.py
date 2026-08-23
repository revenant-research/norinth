"""Notifications: outbox, SMTP invites, signed webhooks, review/gate/incident hooks.

Delivery is exercised against a real in-process SMTP server and a real HTTP
webhook receiver (verifying the HMAC signature), not mocks of smtplib/urllib.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}
BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


# --- tiny real servers ---------------------------------------------------------------


class _SmtpServer:
    """Minimal SMTP server (no TLS) that records messages."""

    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())
        self._loop.run_forever()

    async def _serve(self) -> None:
        async def handle(reader, writer):
            writer.write(b"220 test ESMTP\r\n")
            data, mail_from, rcpts = b"", "", []
            reading = False
            while True:
                line = await reader.readline()
                if not line:
                    break
                if reading:
                    if line == b".\r\n":
                        reading = False
                        self.messages.append({"from": mail_from, "to": rcpts, "raw": data.decode("utf-8", "replace")})
                        writer.write(b"250 OK\r\n")
                    else:
                        data += line
                    continue
                cmd = line.decode().strip()
                up = cmd.upper()
                if up.startswith("EHLO") or up.startswith("HELO"):
                    writer.write(b"250-test\r\n250 AUTH PLAIN LOGIN\r\n")
                elif up.startswith("AUTH"):
                    writer.write(b"235 ok\r\n")
                elif up.startswith("MAIL FROM"):
                    mail_from = cmd.split(":", 1)[1].strip()
                    writer.write(b"250 OK\r\n")
                elif up.startswith("RCPT TO"):
                    rcpts.append(cmd.split(":", 1)[1].strip().strip("<>"))
                    writer.write(b"250 OK\r\n")
                elif up == "DATA":
                    reading, data = True, b""
                    writer.write(b"354 go\r\n")
                elif up == "QUIT":
                    writer.write(b"221 bye\r\n")
                    await writer.drain()
                    writer.close()
                    return
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]

    def start(self) -> _SmtpServer:
        self._thread.start()
        import time

        for _ in range(100):
            if self.port:
                break
            time.sleep(0.02)
        return self


class _HookReceiver:
    def __init__(self) -> None:
        self.received: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                outer.received.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):  # silence
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def smtp(monkeypatch):
    server = _SmtpServer().start()
    monkeypatch.setenv("NORINTH_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("NORINTH_SMTP_PORT", str(server.port))
    monkeypatch.setenv("NORINTH_SMTP_STARTTLS", "0")
    monkeypatch.setenv("NORINTH_SMTP_FROM", "norinth@example.test")
    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://norinth.example.test")
    return server


def _org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": "acme", "name": "Acme Health", "admin_email": "oa@acme.test", "admin_display_name": "OA", "admin_password": "oa-password-1"})
    client = TestClient(app)
    login_and_activate(client, "oa@acme.test", "oa-password-1")
    return client


# --- invites --------------------------------------------------------------------------


def test_invite_is_emailed_and_sets_password_once(super_admin_client, smtp):
    from app.main import app
    from app.services.notifications import deliver_pending
    from fastapi.testclient import TestClient

    org = _org(super_admin_client)
    created = org.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev"}).json()
    assert created["invite_emailed"] is True
    assert created["invite_url"].startswith("https://norinth.example.test/#invite/inv_")
    token = created["invite_url"].rsplit("/", 1)[1]

    assert deliver_pending() == {"sent": 1, "failed": 0}
    assert smtp.messages and smtp.messages[0]["to"] == ["rev@acme.test"]
    import email

    parsed = email.message_from_string(smtp.messages[0]["raw"])
    assert "Acme Health" in parsed["Subject"] and token in parsed.get_payload(decode=True).decode()

    with TestClient(app) as visitor:
        preview = visitor.get(f"/api/auth/invite/{token}").json()
        assert preview["email"] == "rev@acme.test" and preview["organization"] == "Acme Health"
        assert visitor.post("/api/auth/accept-invite", json={"token": token, "password": "short"}).status_code == 422
        accepted = visitor.post("/api/auth/accept-invite", json={"token": token, "password": "a-chosen-password-123"})
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["user"]["must_change_password"] is False
        # Signed in straight away, no forced rotation.
        assert visitor.get("/api/auth/me").status_code == 200
        # Single use.
        assert visitor.post("/api/auth/accept-invite", json={"token": token, "password": "another-password-123"}).status_code == 404
        assert visitor.get(f"/api/auth/invite/{token}").status_code == 404
    # The chosen password works for a normal login.
    with TestClient(app) as again:
        assert again.post("/api/auth/login", json={"email": "rev@acme.test", "password": "a-chosen-password-123"}).status_code == 200
    logs = org.get("/api/audit-logs", params={"action": "auth.accept_invite"}).json()
    assert logs["page"]["total"] == 1
    org.close()


def test_without_smtp_invite_is_returned_and_logged_not_lost(super_admin_client, monkeypatch):
    monkeypatch.delenv("NORINTH_SMTP_HOST", raising=False)
    org = _org(super_admin_client)
    created = org.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev"}).json()
    assert created["invite_emailed"] is False and "invite_url" in created and created["temporary_password"]
    log = org.get("/api/org/notifications").json()
    assert log["smtp_configured"] is False
    assert log["notifications"][0]["status"] == "skipped_no_smtp" and log["notifications"][0]["target"] == "rev@acme.test"
    org.close()


# --- webhooks + hooks ----------------------------------------------------------------


def test_signed_webhooks_receive_gate_and_incident_events(super_admin_client, monkeypatch):
    from app.main import app
    from app.services.notifications import deliver_pending
    from fastapi.testclient import TestClient

    monkeypatch.setenv("NORINTH_PUBLIC_BASE_URL", "https://norinth.example.test")
    receiver = _HookReceiver()
    org = _org(super_admin_client)
    hook = org.post("/api/org/webhooks", json={"name": "siem", "url": f"http://127.0.0.1:{receiver.port}/hook", "events": ["gate.approved", "gate.rejected", "incident.opened", "test"]})
    assert hook.status_code == 201, hook.text
    secret = hook.json()["secret"]
    webhook_id = hook.json()["webhook"]["webhook_id"]
    assert "secret" not in org.get("/api/org/webhooks").json()["webhooks"][0]
    assert org.post("/api/org/webhooks", json={"name": "x", "url": "http://h", "events": ["nope"]}).status_code == 400

    # Test delivery, signed.
    test = org.post(f"/api/org/webhooks/{webhook_id}/test").json()
    assert test["delivered"]["sent"] == 1 and test["last_status"] == "ok"
    body = receiver.received[-1]["body"]
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert receiver.received[-1]["headers"]["X-Norinth-Signature"] == expected
    assert receiver.received[-1]["headers"]["X-Norinth-Event"] == "test"

    # Real events: an incident opened by ingestion, a gate rejected by a human.
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    events = [
        {**BASE, "type": "prompt.event", "trace_id": "t_p", "span_id": "s_p", "timestamp": "2026-08-22T00:00:01Z", "attributes": {"prompt_id": "p", "version": "p1", "artifact_ref": "pr:1", "metadata": META}},
        {**BASE, "type": "deployment.event", "trace_id": "t_d", "span_id": "s_d", "timestamp": "2026-08-22T00:00:02Z", "attributes": {"deployment_id": "dep-1", "version": "v1", "artifact_ref": "img:1", "prompt_version": "p1", "deployment_status": "pending", "metadata": META}},
        {**BASE, "type": "incident.event", "trace_id": "t_i", "span_id": "s_i", "timestamp": "2026-08-22T00:00:03Z", "name": "PHI leak", "attributes": {"title": "PHI in output", "severity": "high", "metadata": META}},
    ]
    assert org.post("/v1/events/batch", json={"events": events}, headers=h).status_code == 200
    gate_id = org.get("/api/deployment-gates").json()["deployment_gates"][0]["gate_id"]
    org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        assert gov.post(f"/api/deployment-gates/{gate_id}/reject", json={"rationale": "missing prompt evidence"}).status_code == 200
    deliver_pending()
    types = [r["headers"]["X-Norinth-Event"] for r in receiver.received]
    assert "incident.opened" in types and "gate.rejected" in types
    rejected = json.loads(next(r["body"] for r in receiver.received if r["headers"]["X-Norinth-Event"] == "gate.rejected"))
    assert rejected["data"]["decided_by"] == "gov@acme.test" and rejected["link"].endswith(f"#gate/{gate_id}")
    # Delivery log shows both sent.
    log = org.get("/api/org/notifications").json()["notifications"]
    assert {e["event_type"] for e in log if e["channel"] == "webhook" and e["status"] == "sent"} >= {"incident.opened", "gate.rejected"}
    org.close()


def test_review_assignment_and_escalation_notify_once(super_admin_client, smtp):
    """Assignment emails the assignee once; escalation emails the assignee and org admins once,
    even though the queue is recomputed on every ingest."""
    from app.services.notifications import deliver_pending
    from app.storage.raw_events import connect

    org = _org(super_admin_client)
    org.post("/api/org/users", json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-password-1"})
    org.post("/api/org/role-assignments", json={"user_ref": "rev@acme.test", "role": "governance_reviewer"})
    # Route intake reviews to reviewers, due in 2 days, escalate 1 day later.
    assert org.post("/api/review-queue-policies", json={"policy_id": "intake", "task_type": "intake_review", "assigned_role": "governance_reviewer", "due_days": 2, "escalation_days": 1}).status_code == 200
    deliver_pending()
    smtp.messages.clear()

    # A high-risk use case through intake creates an intake review routed to a reviewer.
    submitted = org.post("/api/intake", json={"application_name": "Claims", "use_case": "Claims triage", "description": "Triage inbound claims", "intended_purpose": "prioritise claims", "data_sensitivity": "restricted", "autonomy_level": "assistive", "affects_individuals": True, "project": "p1", "environment": "prod"})
    assert submitted.status_code in (200, 201), submitted.text
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    ping = {**BASE, "type": "sdk.health", "trace_id": "t1", "span_id": "s1", "timestamp": "2026-08-22T00:00:00Z", "attributes": {"mode": "observe", "fail_open": True, "failed_sends": 0, "metadata": META}}
    org.post("/v1/events/batch", json={"events": [ping]}, headers=h)  # queue refresh -> assignment
    deliver_pending()
    assigned = [m for m in smtp.messages if "Review assigned to you" in m["raw"]]
    assert len(assigned) == 1 and assigned[0]["to"] == ["rev@acme.test"]

    # Re-ingesting must not re-send the assignment.
    org.post("/v1/events/batch", json={"events": [{**ping, "trace_id": "t2", "span_id": "s2"}]}, headers=h)
    deliver_pending()
    assert len([m for m in smtp.messages if "Review assigned to you" in m["raw"]]) == 1

    # Age the task past its escalation deadline and refresh.
    with connect() as connection:
        connection.execute("UPDATE review_tasks SET created_at = '2020-01-01 00:00:00', due_at = '2020-01-02 00:00:00'")
    org.post("/v1/events/batch", json={"events": [{**ping, "trace_id": "t3", "span_id": "s3"}]}, headers=h)
    org.post("/v1/events/batch", json={"events": [{**ping, "trace_id": "t4", "span_id": "s4"}]}, headers=h)
    deliver_pending()
    escalated = [m for m in smtp.messages if "Review escalated" in m["raw"]]
    recipients = sorted(set(sum((m["to"] for m in escalated), [])))
    assert recipients == ["oa@acme.test", "rev@acme.test"], recipients
    assert len(escalated) == 2  # one per recipient, sent once despite two refreshes
    org.close()


def test_two_workers_never_deliver_the_same_row(super_admin_client):
    """Replica safety: claiming is atomic, so concurrent workers get disjoint
    rows; rows claimed by a dead worker are reclaimed after the stale window."""
    from app.storage import notifications as store
    from app.storage.raw_events import connect

    with connect() as connection:
        for i in range(20):
            store.enqueue(connection, tenant_id="acme", channel="email", event_type="test", target=f"user{i}@acme.test", subject="s", payload={"text": "t"})

    a = store.claim_pending(limit=50, worker_id="replica-a")
    b = store.claim_pending(limit=50, worker_id="replica-b")
    assert len(a) == 20 and b == []  # everything claimed by a; b gets nothing
    assert {row["claimed_by"] for row in a} == {"replica-a"}

    # replica-a dies without finishing; after the stale window replica-b reclaims.
    with connect() as connection:
        connection.execute("UPDATE notification_outbox SET claimed_at = '2020-01-01 00:00:00' WHERE claimed_by = 'replica-a'")
    reclaimed = store.claim_pending(limit=50, worker_id="replica-b")
    assert len(reclaimed) == 20 and {row["claimed_by"] for row in reclaimed} == {"replica-b"}

    # Interleaved claiming with a smaller limit stays disjoint.
    with connect() as connection:
        connection.execute("UPDATE notification_outbox SET status = 'pending', claimed_by = NULL, claimed_at = NULL")
    first = store.claim_pending(limit=10, worker_id="replica-a")
    second = store.claim_pending(limit=10, worker_id="replica-b")
    ids_a = {row["id"] for row in first}
    ids_b = {row["id"] for row in second}
    assert len(ids_a) == 10 and len(ids_b) == 10 and not (ids_a & ids_b)
