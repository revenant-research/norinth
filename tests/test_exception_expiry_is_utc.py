"""exception expiry is stored as a utc instant

expires_at is compared as text in sql. text order equals time order only when
every value carries the same offset, so a value written with +05:00 read as
expiring five hours after it had actually lapsed, and in that window a release
gate could be approved on a lapsed risk acceptance
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from tests.helpers import login_and_activate


def _org_with_finding(super_admin_client):
    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    org = TestClient(app)
    org.__enter__()
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]
    org.post("/api/org/users", json={"email": "risk@acme.test", "display_name": "Risk", "password": "risk-pw-123456"})
    org.post("/api/org/role-assignments", json={"user_ref": "risk@acme.test", "role": "risk_owner"})
    sent = org.post("/v1/events/batch", json={"events": [{
        "type": "model.call", "schema_version": "2026-01", "trace_id": "trc_1", "span_id": "spn_1",
        "timestamp": "2026-08-22T00:00:02Z", "service": "svc", "environment": "prod", "project": "p1",
        "status": "success",
        "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 5, "output_tokens": 5},
                       "metadata": {"tenant_id": "acme", "application_name": "PayApp", "workflow_name": "wf"}},
    }]}, headers={"Authorization": f"Bearer {token}"})
    assert sent.status_code == 200, sent.text
    org.close()
    with connect() as connection:
        finding = connection.execute("SELECT finding_id FROM risk_findings WHERE tenant_id = 'acme'").fetchone()
    assert finding is not None, "the model call produced no finding"
    risk = TestClient(app)
    risk.__enter__()
    login_and_activate(risk, "risk@acme.test", "risk-pw-123456")
    return risk, finding["finding_id"]


def test_an_offset_expiry_is_stored_in_utc(super_admin_client):
    from app.storage.raw_events import connect

    risk, finding_id = _org_with_finding(super_admin_client)
    instant = (datetime.now(UTC) + timedelta(hours=1)).replace(microsecond=0)
    local = instant.astimezone(timezone(timedelta(hours=5)))
    created = risk.post("/api/exceptions", json={
        "target_type": "risk_finding", "target_id": finding_id,
        "reason": "accepted for the pilot period with monitoring in place",
        "compensating_control": "weekly manual review of flagged outputs",
        "expires_at": local.isoformat(),
    })
    assert created.status_code == 200, created.text
    assert created.json()["exception"]["expires_at"] == instant.isoformat()
    with connect() as connection:
        stored = connection.execute("SELECT expires_at FROM governance_exceptions").fetchone()["expires_at"]
    assert stored == instant.isoformat()
    assert stored.endswith("+00:00")
    risk.close()


def test_a_date_only_expiry_is_midnight_utc(super_admin_client):
    risk, finding_id = _org_with_finding(super_admin_client)
    created = risk.post("/api/exceptions", json={
        "target_type": "risk_finding", "target_id": finding_id,
        "reason": "accepted for the pilot period with monitoring in place",
        "compensating_control": "weekly manual review of flagged outputs",
        "expires_at": "2099-12-31",
    })
    assert created.status_code == 200, created.text
    assert created.json()["exception"]["expires_at"] == "2099-12-31T00:00:00+00:00"
    risk.close()


@pytest.mark.parametrize("value", ["not-a-date", "2026-13-01", ""])
def test_an_unparseable_expiry_is_refused(super_admin_client, value):
    risk, finding_id = _org_with_finding(super_admin_client)
    created = risk.post("/api/exceptions", json={
        "target_type": "risk_finding", "target_id": finding_id,
        "reason": "accepted for the pilot period with monitoring in place",
        "compensating_control": "weekly manual review of flagged outputs",
        "expires_at": value,
    })
    assert created.status_code in {400, 422}, created.text
    risk.close()


def test_migration_normalises_legacy_offsets_so_they_expire_on_time(fresh_db):
    """a row written before normalisation with a +05:00 offset that has lapsed
    in utc but still reads as future as text"""
    from app.storage.migrations import _0028_exception_expiry_utc
    from app.storage.raw_events import connect
    from app.storage.workflow import expire_due_exceptions

    lapsed = (datetime.now(UTC) - timedelta(hours=2)).replace(microsecond=0)
    legacy = lapsed.astimezone(timezone(timedelta(hours=5))).isoformat()
    assert legacy > datetime.now(UTC).isoformat()  # the text compare says "not yet"
    with connect() as connection:
        connection.execute(
            "INSERT INTO governance_exceptions (exception_id, tenant_id, project, environment, application_name, "
            "target_type, target_id, reason, compensating_control, expires_at, status, actor_ref, created_at, updated_at) "
            "VALUES ('e-legacy', 'acme', 'p1', 'prod', 'PayApp', 'risk_finding', 'rf-1', 'r', 'c', ?, 'active', "
            "'risk@acme.test', datetime('now'), datetime('now'))",
            (legacy,),
        )
    assert expire_due_exceptions() == 0
    with connect() as connection:
        _0028_exception_expiry_utc(connection)
        stored = connection.execute("SELECT expires_at FROM governance_exceptions WHERE exception_id = 'e-legacy'").fetchone()
    assert stored["expires_at"] == lapsed.isoformat()
    assert expire_due_exceptions() == 1


def test_scope_indexes_exist_on_a_fresh_database(fresh_db):
    """migration 10 rebuilt these tables and dropped the baseline indexes"""
    from app.storage import db
    from app.storage.raw_events import connect

    wanted = {
        "idx_governance_incidents_scope", "idx_governance_incidents_status",
        "idx_governance_deployments_scope", "idx_prompt_templates_scope",
    }
    with connect() as connection:
        if db.is_postgres():
            rows = connection.execute("SELECT indexname AS name FROM pg_indexes WHERE schemaname = 'public'").fetchall()
        else:
            rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'index'").fetchall()
    assert wanted <= {row["name"] for row in rows}
