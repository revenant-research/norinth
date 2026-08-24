"""clock-driven governance state advances without waiting for telemetry

review sla and exception expiry used to be recomputed only while ingesting a
batch, so an application that had gone quiet never raised an overdue review and
never lapsed an expired risk acceptance
"""

from __future__ import annotations

from tests.helpers import login_and_activate


def _org_with_a_review_task(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        # a reviewer to route the intake to; an unassigned task never ages
        org.post("/api/org/users",
                 json={"email": "rev@acme.test", "display_name": "Rev", "password": "rev-password-1"})
        org.post("/api/org/role-assignments",
                 json={"user_ref": "rev@acme.test", "role": "governance_reviewer"})
        submitted = org.post("/api/intake", json={
            "application_name": "PayApp", "use_case": "score inbound payment risk",
            "description": "flags payments for manual review",
            "intended_purpose": "reduce fraud losses",
            "data_sensitivity": "confidential", "autonomy_level": "supervised",
            "affects_individuals": True, "project": "p1", "environment": "prod",
        })
        assert submitted.status_code == 200, submitted.text


def test_maintenance_pass_escalates_an_overdue_review(super_admin_client):
    from app.services import maintenance
    from app.storage.raw_events import connect

    _org_with_a_review_task(super_admin_client)

    with connect() as connection:
        task = connection.execute(
            "SELECT task_id, escalation_status FROM review_tasks WHERE task_type = 'intake_review'"
        ).fetchone()
        assert task is not None
        task_id = task["task_id"]
        assert task["escalation_status"] == "on_track", dict(task)
        # the review sits untouched well past its due and escalation dates
        connection.execute(
            "UPDATE review_tasks SET created_at = '2020-01-01T00:00:00+00:00' WHERE task_id = ?",
            (task_id,),
        )

    # no telemetry: the maintenance pass alone has to age the queue
    result = maintenance.run_once()
    assert result["skipped"] is False

    with connect() as connection:
        after = connection.execute(
            "SELECT escalation_status, escalated_at FROM review_tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
    assert after["escalation_status"] == "escalated", dict(after)
    assert after["escalated_at"] is not None


def test_maintenance_pass_expires_a_lapsed_exception(super_admin_client):
    from app.main import app
    from app.services import maintenance
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
        org.post("/api/org/users",
                 json={"email": "gov@acme.test", "display_name": "Gov", "password": "gov-password-1"})
        org.post("/api/org/role-assignments",
                 json={"user_ref": "gov@acme.test", "role": "governance_admin"})
        ingested = org.post("/v1/events/batch", json={"events": [{
            "type": "model.call", "schema_version": "2026-01", "trace_id": "t1", "span_id": "s1",
            "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
            "status": "success",
            "attributes": {"provider": "openai", "model": "gpt-4o",
                           "usage": {"input_tokens": 5, "output_tokens": 5},
                           "metadata": {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}},
        }]}, headers={"Authorization": f"Bearer {token}"})
        assert ingested.status_code == 200, ingested.text

    with connect() as connection:
        finding = connection.execute(
            "SELECT finding_id FROM risk_findings WHERE status IN ('open', 'mitigation_required') LIMIT 1"
        ).fetchone()
        assert finding is not None
        finding_id = finding["finding_id"]

    with TestClient(app) as gov:
        login_and_activate(gov, "gov@acme.test", "gov-password-1")
        waived = gov.post("/api/exceptions", json={
            "target_type": "risk_finding", "target_id": finding_id,
            "reason": "accepted while the fix is scheduled",
            "compensating_control": "weekly manual review by the payments lead",
            "expires_at": "2099-12-31",
        })
        assert waived.status_code == 200, waived.text

    with connect() as connection:
        connection.execute(
            "UPDATE governance_exceptions SET expires_at = '2000-01-01' WHERE target_id = ?", (finding_id,)
        )

    # no telemetry and nobody opening a page: the pass alone must lapse it
    assert maintenance.run_once()["expired_exceptions"] >= 1

    with connect() as connection:
        exception_row = connection.execute(
            "SELECT status FROM governance_exceptions WHERE target_id = ?", (finding_id,)
        ).fetchone()
        finding_row = connection.execute(
            "SELECT status FROM risk_findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    assert exception_row["status"] == "expired"
    assert finding_row["status"] == "open"


def test_worker_is_disabled_by_env(monkeypatch):
    from app.services import maintenance

    monkeypatch.setattr(maintenance, "_worker_started", False)
    monkeypatch.setenv("NORINTH_MAINTENANCE_WORKER", "0")
    maintenance.start_worker()
    assert maintenance._worker_started is False
