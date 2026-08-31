# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""detail views read the rows they show, not every event in scope

the detail builders paged the whole scope into memory and filtered in python, so
their cost tracked total event count and they stopped at the scan ceiling. these
tests pin the narrowing to sql by counting the rows the storage layer hands back
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage import raw_events  # noqa: E402

from tests.helpers import login_and_activate  # noqa: E402

BASE = {
    "schema_version": "2026-01",
    "timestamp": "2026-08-22T00:00:00Z",
    "service": "svc",
    "environment": "prod",
    "project": "p1",
}


def _org(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, token


def _seed(org, token, apps=("wanted", "noise-a", "noise-b"), per_app=6):
    events = []
    for app_name in apps:
        for index in range(per_app):
            uid = f"{app_name}-{index}"
            events.append(
                {
                    **BASE,
                    "type": "model.call",
                    "trace_id": f"trc-{uid}",
                    "span_id": f"spn-{uid}",
                    "name": f"wf-{app_name}",
                    "attributes": {
                        "provider": "openai",
                        "model": "gpt-4o",
                        "metadata": {
                            "tenant_id": "acme",
                            "application_name": app_name,
                            "workflow_name": f"wf-{app_name}",
                        },
                    },
                }
            )
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


@pytest.fixture()
def counted_reads(monkeypatch):
    """record how many rows every list_events call returns"""
    seen: list[int] = []
    original = raw_events.list_events

    def spy(**kwargs):
        rows = original(**kwargs)
        seen.append(len(rows))
        return rows

    monkeypatch.setattr(raw_events, "list_events", spy)
    import app.services.governance as governance

    monkeypatch.setattr(governance, "list_events", spy)
    return seen


def test_application_detail_reads_only_its_own_events(super_admin_client, counted_reads):
    from app.schemas.events import ScopeFilter
    from app.services.governance import build_application_detail
    from app.storage.entities import list_applications

    org, token = _org(super_admin_client)
    _seed(org, token)
    scope = ScopeFilter(tenant_id="acme")
    wanted = next(a for a in list_applications(tenant_id="acme") if a["application_name"] == "wanted")

    counted_reads.clear()
    detail = build_application_detail(scope, wanted["entity_id"])

    assert detail is not None
    # 18 events exist across three applications; nothing may read past this one's 6
    assert max(counted_reads, default=0) <= 6, counted_reads
    assert {trace["trace_id"] for trace in detail["traces"]} == {f"trc-wanted-{i}" for i in range(6)}
    org.close()


def test_workflow_detail_reads_only_its_own_events(super_admin_client, counted_reads):
    from app.schemas.events import ScopeFilter
    from app.services.governance import build_workflow_detail
    from app.storage.entities import list_workflows

    org, token = _org(super_admin_client)
    _seed(org, token)
    scope = ScopeFilter(tenant_id="acme")
    wanted = next(w for w in list_workflows(tenant_id="acme") if w["workflow_name"] == "wf-wanted")

    counted_reads.clear()
    detail = build_workflow_detail(scope, wanted["entity_id"])

    assert detail is not None
    assert max(counted_reads, default=0) <= 6, counted_reads
    assert len(detail["model_calls"]) == 6
    org.close()


def test_trace_detail_reads_only_that_trace(super_admin_client, counted_reads):
    from app.schemas.events import ScopeFilter
    from app.services.governance import build_trace_detail

    org, token = _org(super_admin_client)
    _seed(org, token)
    scope = ScopeFilter(tenant_id="acme")

    counted_reads.clear()
    detail = build_trace_detail(scope, "trc-wanted-0")

    assert detail is not None
    assert detail["trace_id"] == "trc-wanted-0"
    # one event carries this trace; the index on trace_id makes that one row
    assert max(counted_reads, default=0) == 1, counted_reads
    org.close()


def test_systems_are_rolled_up_without_reading_events(super_admin_client, counted_reads):
    from app.schemas.events import ScopeFilter
    from app.services.governance import build_systems

    org, token = _org(super_admin_client)
    _seed(org, token)

    counted_reads.clear()
    systems = build_systems(ScopeFilter(tenant_id="acme"))["systems"]

    assert counted_reads == [], "the system rollup should group in sql, not page events"
    assert systems and systems[0]["events"] == 18
    assert systems[0]["models"] == ["gpt-4o"]
    assert systems[0]["vendors"] == ["openai"]
    org.close()


def test_trace_detail_is_scoped_to_the_tenant(super_admin_client):
    """narrowing moved into the same where clause that carries the scope"""
    from app.schemas.events import ScopeFilter
    from app.services.governance import build_trace_detail

    org, token = _org(super_admin_client)
    _seed(org, token)
    assert build_trace_detail(ScopeFilter(tenant_id="acme"), "trc-wanted-0") is not None
    assert build_trace_detail(ScopeFilter(tenant_id="other"), "trc-wanted-0") is None
    org.close()
