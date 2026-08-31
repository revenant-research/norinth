# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""list endpoints fetch one page, not the whole table

paginate() sliced an already-materialised list, so the page parameters shaped
the response without reducing the work and a paged request cost the same as an
unpaged one. these tests pin the window to sql by counting the rows the storage
layer returns
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage import scoping  # noqa: E402

from tests.helpers import login_and_activate  # noqa: E402

BASE = {
    "schema_version": "2026-01",
    "timestamp": "2026-08-22T00:00:00Z",
    "service": "svc",
    "environment": "prod",
    "project": "p1",
}
SEEDED = 25


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


def _seed(org, token):
    """one tool call and one retrieval per trace, so two observed-event tables fill"""
    events = []
    for index in range(SEEDED):
        meta = {"tenant_id": "acme", "application_name": "app", "workflow_name": "wf"}
        events.append({**BASE, "type": "tool.call", "trace_id": f"t{index}", "span_id": f"s{index}",
                       "name": f"tool-{index}", "attributes": {"tool_name": f"tool-{index}", "metadata": meta}})
        events.append({**BASE, "type": "retrieval.call", "trace_id": f"r{index}", "span_id": f"rs{index}",
                       "name": f"kb-{index}", "attributes": {"retriever": f"kb-{index}",
                                                             "document_count": 1, "metadata": meta}})
    resp = org.post("/v1/events/batch", json={"events": events}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text


@pytest.fixture()
def rows_read(monkeypatch):
    seen: list[int] = []
    original = scoping.scoped_rows

    def spy(*args, **kwargs):
        rows = original(*args, **kwargs)
        seen.append(len(rows))
        return rows

    monkeypatch.setattr(scoping, "scoped_rows", spy)
    import app.storage.entities as entities

    monkeypatch.setattr(entities, "scoped_rows", spy)
    return seen


def test_a_page_reads_only_that_page(super_admin_client, rows_read):
    org, token = _org(super_admin_client)
    _seed(org, token)

    rows_read.clear()
    body = org.get("/api/tools", params={"limit": 5, "offset": 0}).json()

    assert len(body["tools"]) == 5
    assert body["page"] == {"offset": 0, "limit": 5, "total": SEEDED, "has_more": True}
    # 50 observed events exist; a five-row page must not read past five
    assert max(rows_read, default=0) <= 5, rows_read
    org.close()


def test_pages_are_disjoint_and_cover_the_set(super_admin_client):
    org, token = _org(super_admin_client)
    _seed(org, token)

    seen: list[str] = []
    offset = 0
    while True:
        body = org.get("/api/tools", params={"limit": 7, "offset": offset}).json()
        seen.extend(row["tool_name"] for row in body["tools"])
        if not body["page"]["has_more"]:
            break
        offset += 7

    assert len(seen) == SEEDED
    assert len(set(seen)) == SEEDED, "a row appeared on two pages"
    org.close()


def test_total_counts_the_matching_rows_not_the_table(super_admin_client):
    """tools and retrievals share one table; each count must see only its own type"""
    org, token = _org(super_admin_client)
    _seed(org, token)

    assert org.get("/api/tools", params={"limit": 1}).json()["page"]["total"] == SEEDED
    assert org.get("/api/retrievals", params={"limit": 1}).json()["page"]["total"] == SEEDED
    org.close()


def test_last_page_reports_no_more(super_admin_client):
    org, token = _org(super_admin_client)
    _seed(org, token)

    body = org.get("/api/tools", params={"limit": 10, "offset": 20}).json()
    assert len(body["tools"]) == 5
    assert body["page"]["has_more"] is False
    org.close()


def test_offset_past_the_end_is_an_empty_page(super_admin_client):
    org, token = _org(super_admin_client)
    _seed(org, token)

    body = org.get("/api/tools", params={"limit": 10, "offset": 500}).json()
    assert body["tools"] == []
    assert body["page"]["total"] == SEEDED
    assert body["page"]["has_more"] is False
    org.close()


@pytest.mark.parametrize(
    "path,key",
    [("/api/tools", "tools"), ("/api/retrievals", "retrievals"), ("/api/risk-register", "risks"),
     ("/api/control-evidence", "controls"), ("/api/incidents", "incidents"), ("/api/decisions", "decisions"),
     ("/api/exceptions", "exceptions"), ("/api/owner-assignments", "owners"),
     ("/api/review-tasks", "review_tasks"), ("/api/deployment-gates", "deployment_gates")],
)
def test_every_paged_endpoint_reports_a_page(super_admin_client, path, key):
    org, token = _org(super_admin_client)
    _seed(org, token)

    body = org.get(path, params={"limit": 3, "offset": 0}).json()
    assert key in body
    assert set(body["page"]) == {"offset", "limit", "total", "has_more"}
    assert len(body[key]) <= 3
    org.close()
