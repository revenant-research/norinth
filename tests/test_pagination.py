"""Server-side pagination on list endpoints.

The audit flagged unbounded list responses (API and UI). Every list endpoint
now accepts ``offset``/``limit`` and returns ``page`` metadata while keeping the
original list key for backward compatibility. Event-backed endpoints page at the
SQL level; entity-backed endpoints page the materialised list.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _sdk_health(index: int) -> dict:
    return {
        "type": "sdk.health",
        "schema_version": "2026-01",
        "trace_id": f"trc_{index:04d}",
        "span_id": f"spn_{index:04d}",
        "timestamp": f"2026-08-22T00:{index // 60:02d}:{index % 60:02d}Z",
        "service": f"svc-{index:04d}",
        "environment": "prod",
        "project": "p1",
        "attributes": {"mode": "observe", "fail_open": True, "failed_sends": 0, "metadata": {}},
    }


@pytest.fixture
def org_client(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "a@acme.test",
            "admin_display_name": "Acme admin",
            "admin_password": "acme-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    resp = org.post(
        "/v1/events/batch",
        json={"events": [_sdk_health(i) for i in range(25)]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    try:
        yield org
    finally:
        org.close()


def test_events_are_paged_at_sql_level_newest_first(org_client):
    first = org_client.get("/api/events", params={"limit": 10}).json()
    assert first["page"] == {"offset": 0, "limit": 10, "total": 25, "has_more": True}
    assert len(first["events"]) == 10
    # Offset 0 is the newest window; within the window events are chronological.
    traces = [e["trace_id"] for e in first["events"]]
    assert traces == [f"trc_{i:04d}" for i in range(15, 25)]

    last = org_client.get("/api/events", params={"limit": 10, "offset": 20}).json()
    assert last["page"] == {"offset": 20, "limit": 10, "total": 25, "has_more": False}
    assert [e["trace_id"] for e in last["events"]] == [f"trc_{i:04d}" for i in range(0, 5)]

    # Walking every page yields each event exactly once.
    seen: list[str] = []
    offset = 0
    while True:
        body = org_client.get("/api/events", params={"limit": 7, "offset": offset}).json()
        seen.extend(e["trace_id"] for e in body["events"])
        if not body["page"]["has_more"]:
            break
        offset += body["page"]["limit"]
    assert sorted(seen) == sorted(f"trc_{i:04d}" for i in range(25))
    assert len(seen) == 25


def test_sdk_health_and_traces_expose_page_metadata(org_client):
    health = org_client.get("/api/sdk-health", params={"limit": 5}).json()
    assert health["page"]["total"] == 25 and len(health["sdk_health"]) == 5

    traces = org_client.get("/api/traces", params={"limit": 5, "offset": 23}).json()
    assert traces["page"]["total"] == 25
    assert len(traces["traces"]) == 2
    assert traces["page"]["has_more"] is False


def test_entity_lists_keep_original_key_and_add_page(org_client):
    for path, key in [
        ("/api/retrievals", "retrievals"),
        ("/api/tools", "tools"),
        ("/api/guardrails", "guardrails"),
        ("/api/evals", "evals"),
        ("/api/agents", "agents"),
        ("/api/risk-register", "risks"),
        ("/api/control-evidence", "controls"),
        ("/api/review-tasks", "review_tasks"),
        ("/api/decisions", "decisions"),
        ("/api/exceptions", "exceptions"),
    ]:
        body = org_client.get(path).json()
        assert key in body, path
        assert body["page"]["offset"] == 0 and body["page"]["limit"] == 200, path
        assert body["page"]["total"] == len(body[key]), path
        assert body["page"]["has_more"] is False, path


def test_limit_bounds_are_enforced(org_client):
    assert org_client.get("/api/events", params={"limit": 0}).status_code == 422
    assert org_client.get("/api/events", params={"limit": 5000}).status_code == 422
    assert org_client.get("/api/events", params={"offset": -1}).status_code == 422
    # Default is bounded even without parameters.
    body = org_client.get("/api/events").json()
    assert body["page"]["limit"] == 200


def test_audit_logs_page_with_totals(org_client):
    body = org_client.get("/api/audit-logs", params={"limit": 2}).json()
    assert body["page"]["limit"] == 2
    assert len(body["audit_logs"]) == 2
    assert body["page"]["total"] >= 3  # login, password change, key creation at minimum
    assert body["page"]["has_more"] is True
    second = org_client.get("/api/audit-logs", params={"limit": 2, "offset": 2}).json()
    assert {e["id"] for e in second["audit_logs"]}.isdisjoint({e["id"] for e in body["audit_logs"]})
    # A tenant admin cannot widen the scope with tenant_id.
    other = org_client.get("/api/audit-logs", params={"tenant_id": "beta"}).json()
    assert all(e["tenant_id"] == "acme" for e in other["audit_logs"])
