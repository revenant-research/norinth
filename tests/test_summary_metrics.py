"""Summary metrics and trace lists are computed in SQL, not a capped window (H9).

The dashboard summary used to load a 10,000-row window and count in Python, so
counts were wrong past that size and reported "10,000" forever; the trace list
loaded every event and sliced in Python. These verify the counts are exact and
the trace list pages with a correct total.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _event(i: int, etype: str, status: str = "success", trace: str | None = None) -> dict:
    return {
        "type": etype,
        "schema_version": "2026-01",
        "trace_id": trace or f"trc-{i}",
        "span_id": f"spn-{i}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "status": status,
        "attributes": {"metadata": {}},
    }


@pytest.fixture
def org_with_events(super_admin_client):
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
    events = []
    # 6 model.calls (2 errors), 3 guardrail.decisions, across 3 traces.
    for i in range(6):
        events.append(_event(i, "model.call", status="error" if i < 2 else "success", trace=f"t{i % 3}"))
    for i in range(3):
        events.append(_event(100 + i, "guardrail.decision", trace=f"t{i}"))
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    try:
        yield org
    finally:
        org.close()


def test_summary_counts_are_exact(org_with_events):
    summary = org_with_events.get("/api/summary").json()
    assert summary["events"] == 9
    assert summary["model_calls"] == 6
    assert summary["guardrail_decisions"] == 3
    assert summary["errors"] == 2
    assert summary["systems"] == 1


def test_traces_paginate_with_correct_total(org_with_events):
    first = org_with_events.get("/api/traces", params={"limit": 2}).json()
    assert first["page"]["total"] == 3  # three distinct traces
    assert first["page"]["has_more"] is True
    assert len(first["traces"]) == 2
    # Each trace carries a real event count; the busiest trace comes first.
    assert first["traces"][0]["event_count"] >= first["traces"][1]["event_count"]

    second = org_with_events.get("/api/traces", params={"offset": 2, "limit": 2}).json()
    assert len(second["traces"]) == 1
    assert second["page"]["has_more"] is False
    seen = {t["trace_id"] for t in first["traces"]} | {t["trace_id"] for t in second["traces"]}
    assert seen == {"t0", "t1", "t2"}
