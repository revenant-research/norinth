"""response hardening headers and request-size limits"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.schemas.events import MAX_BATCH_EVENTS  # noqa: E402


def _event(index: int) -> dict:
    return {
        "type": "sdk.health",
        "schema_version": "2026-01",
        "trace_id": f"t{index}",
        "span_id": f"s{index}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {"mode": "observe", "metadata": {}},
    }


def test_hardening_headers_present_on_dashboard(client):
    resp = client.get("/")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_only_over_https(client):
    # testclient speaks http, so hsts must be absent
    assert "Strict-Transport-Security" not in client.get("/").headers


def test_docs_exempt_from_csp_but_keep_other_headers():
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        resp = tc.get("/openapi.json")
    assert "Content-Security-Policy" not in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_oversized_body_rejected_by_content_length(client):
    huge = str(20 * 1024 * 1024)
    resp = client.post(
        "/v1/events/batch",
        content=b"{}",
        headers={"Content-Length": huge, "Authorization": "Bearer nrk_x"},
    )
    assert resp.status_code == 413


def test_batch_over_cap_is_rejected(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

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
    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
        resp = org.post(
            "/v1/events/batch",
            json={"events": [_event(i) for i in range(MAX_BATCH_EVENTS + 1)]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422, resp.text
