"""a governance change and the audit entry that describes it are one unit

the routes used to save the change in one transaction and append the audit
entry in another. if the append failed, the change stayed and the record of
it was never written. inside a unit of work the two commit or roll back
together, and the checkpoint journal is written only after the commit
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests.helpers import login_and_activate

KEY = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
INCIDENT_ID = "INC-1"


def _org_with_incident(super_admin_client) -> TestClient:
    from app.main import app

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        org.post("/api/org/users", json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-pw-123456"})
        org.post("/api/org/role-assignments", json={"user_ref": "gov@acme.test", "role": "governance_admin"})
        sent = org.post(
            "/v1/events/batch",
            json={
                "events": [
                    {
                        "type": "incident.event",
                        "schema_version": "2026-01",
                        "trace_id": "trc_1",
                        "span_id": "spn_1",
                        "timestamp": "2026-08-22T00:00:00Z",
                        "service": "svc",
                        "environment": "prod",
                        "project": "p1",
                        "status": "error",
                        "attributes": {
                            "incident_id": INCIDENT_ID,
                            "title": "Bad summary",
                            "severity": "High",
                            "incident_status": "open",
                            "metadata": {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"},
                        },
                    }
                ]
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert sent.status_code == 200, sent.text
    # the server's own error becomes a 500 here, as it would for a real client
    gov = TestClient(app, raise_server_exceptions=False)
    gov.__enter__()
    login_and_activate(gov, "gov@acme.test", "gov-pw-123456")
    return gov


def _incident_status() -> str:
    from app.storage.raw_events import connect

    with connect() as connection:
        return connection.execute(
            "SELECT status FROM governance_incidents WHERE incident_id = ?", (INCIDENT_ID,)
        ).fetchone()["status"]


def _count(table: str, where: str = "1=1") -> int:
    from app.storage.raw_events import connect

    with connect() as connection:
        return int(connection.execute(f"SELECT COUNT(*) AS n FROM {table} WHERE {where}").fetchone()["n"])


def test_a_failed_audit_append_leaves_the_incident_open_and_no_decision_behind(super_admin_client, monkeypatch):
    from app.storage import audit

    gov = _org_with_incident(super_admin_client)
    decisions_before = _count("governance_decisions")
    audits_before = _count("audit_logs")

    def refuse(*args, **kwargs):
        raise RuntimeError("Audit database contradicts the retained checkpoint")

    monkeypatch.setattr(audit, "_compute_row_hmac", refuse)
    closed = gov.post(f"/api/incidents/{INCIDENT_ID}/close", json={"rationale": "resolved after the fix shipped"})
    assert closed.status_code == 500, closed.text

    assert _incident_status() == "open"
    assert _count("governance_decisions") == decisions_before
    assert _count("audit_logs") == audits_before
    # nothing was announced for a change that did not happen
    assert _count("notification_outbox", "event_type = 'incident.closed'") == 0
    gov.close()


def test_a_successful_close_commits_the_incident_decision_and_audit_entry_together(super_admin_client):
    from app.storage.audit import verify_audit_chain

    gov = _org_with_incident(super_admin_client)
    closed = gov.post(f"/api/incidents/{INCIDENT_ID}/close", json={"rationale": "resolved after the fix shipped"})
    assert closed.status_code == 200, closed.text
    assert _incident_status() == "closed"
    assert _count("governance_decisions", "target_type = 'incident'") == 1
    assert _count("audit_logs", "action = 'incident.close'") == 1
    assert verify_audit_chain()["ok"] is True
    gov.close()


def test_a_failed_audit_append_leaves_a_control_override_unwritten(super_admin_client):
    from app.main import app
    from app.storage import audit

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    with TestClient(app, raise_server_exceptions=False) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        sample = org.get("/api/control-catalog").json()["controls"][0]["control_id"]
        body = {
            "control_id": sample,
            "name": "Loosened",
            "evidence_event_types": ["model.call"],
            "required_fields": [],
            "rationale": "r",
        }
        with pytest.MonkeyPatch.context() as broken:
            broken.setattr(audit, "_compute_row_hmac", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no")))
            assert org.post("/api/control-catalog", json=body).status_code == 500
        overrides = [c for c in org.get("/api/control-catalog").json()["controls"] if c["control_id"] == sample]
        assert overrides and overrides[0]["name"] != "Loosened"


def test_unit_of_work_commits_all_or_nothing(fresh_db):
    from app.storage.audit import record_audit
    from app.storage.raw_events import connect
    from app.storage.unit_of_work import unit_of_work
    from app.storage.workflow import upsert_owner_policy

    with pytest.raises(RuntimeError, match="abandon"):
        with unit_of_work():
            upsert_owner_policy(
                {
                    "policy_id": "p-rolled-back",
                    "subject_type": "application",
                    "owner_role": "business_owner",
                    "applies_to_status": None,
                    "source": "configured",
                },
                "acme",
            )
            record_audit(actor_ref="t", action="owner_policy.configure", tenant_id="acme")
            raise RuntimeError("abandon")
    with connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) AS n FROM owner_assignment_policies WHERE policy_id = 'p-rolled-back'"
            ).fetchone()["n"]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'owner_policy.configure'"
            ).fetchone()["n"]
            == 0
        )

    with unit_of_work():
        upsert_owner_policy(
            {
                "policy_id": "p-kept",
                "subject_type": "application",
                "owner_role": "business_owner",
                "applies_to_status": None,
                "source": "configured",
            },
            "acme",
        )
        record_audit(actor_ref="t", action="owner_policy.configure", tenant_id="acme")
        record_audit(actor_ref="t", action="owner_policy.configure", tenant_id="acme", target_id="second")
    with connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) AS n FROM owner_assignment_policies WHERE policy_id = 'p-kept'"
            ).fetchone()["n"]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) AS n FROM audit_logs WHERE action = 'owner_policy.configure'"
            ).fetchone()["n"]
            == 2
        )


def test_two_audit_entries_in_one_unit_chain_correctly(fresh_db):
    from app.storage.audit import record_audit, verify_audit_chain
    from app.storage.unit_of_work import unit_of_work

    with unit_of_work():
        record_audit(actor_ref="t", action="first")
        record_audit(actor_ref="t", action="second")
    record_audit(actor_ref="t", action="third")
    assert verify_audit_chain()["ok"] is True


def test_the_checkpoint_journal_is_written_only_after_the_commit(fresh_db, tmp_path, monkeypatch):
    from app.storage.audit import record_audit, verify_audit_chain
    from app.storage.unit_of_work import unit_of_work

    journal = tmp_path / "heads.jsonl"
    monkeypatch.setenv("NORINTH_SECRET_KEY", KEY)
    monkeypatch.setenv("NORINTH_AUDIT_CHECKPOINT_PATH", str(journal))
    record_audit(actor_ref="t", action="anchor")
    anchored = json.loads(journal.read_text().splitlines()[-1])

    with pytest.raises(RuntimeError, match="abandon"):
        with unit_of_work():
            record_audit(actor_ref="t", action="never")
            raise RuntimeError("abandon")
    assert json.loads(journal.read_text().splitlines()[-1]) == anchored  # untouched by the rollback
    assert verify_audit_chain()["ok"] is True

    with unit_of_work():
        record_audit(actor_ref="t", action="kept-1")
        record_audit(actor_ref="t", action="kept-2")
    latest = json.loads(journal.read_text().splitlines()[-1])
    assert latest["count"] == anchored["count"] + 2
    assert verify_audit_chain()["ok"] is True
    assert verify_audit_chain()["completeness_ok"] is True


def test_a_rollback_inside_a_unit_is_refused(fresh_db):
    from app.storage.raw_events import connect
    from app.storage.unit_of_work import unit_of_work

    with pytest.raises(RuntimeError, match="not possible"):
        with unit_of_work(), connect() as connection:
            connection.rollback()


def test_a_unit_inside_a_unit_joins_it(fresh_db):
    from app.storage import db
    from app.storage.unit_of_work import unit_of_work

    with unit_of_work() as outer, unit_of_work() as inner:
        assert inner is outer
        assert db.current_unit() is outer
    assert db.current_unit() is None
