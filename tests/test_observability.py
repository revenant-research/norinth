"""metrics and structured logging for an SLA

the F500 evaluation's ops verdict: no metrics, no structured logs, no way to
see the platform is healthy short of reading the database. /metrics serves
prometheus text (never anonymously — labels carry tenant ids), request ids
follow every request, and the audit chain streams to stdout for a SIEM.
"""

from __future__ import annotations

import json
import logging
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant,
            "name": tenant,
            "admin_email": f"a@{tenant}.test",
            "admin_display_name": "A",
            "admin_password": f"{tenant}-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, {"Authorization": f"Bearer {token}"}


def test_metrics_is_never_anonymous(super_admin_client, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.delenv("NORINTH_METRICS_TOKEN", raising=False)
    anonymous = TestClient(app)
    assert anonymous.get("/metrics").status_code == 403
    anonymous.close()

    # an org admin is tenant plane, not operator plane
    org, _ = _org(super_admin_client, "acme")
    assert org.get("/metrics").status_code == 403
    org.close()

    # the platform administrator can read
    assert super_admin_client.get("/metrics").status_code == 200


def test_metrics_scraper_token(super_admin_client, monkeypatch):
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.setenv("NORINTH_METRICS_TOKEN", "scraper-secret")
    scraper = TestClient(app)
    assert scraper.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 403
    response = scraper.get("/metrics", headers={"Authorization": "Bearer scraper-secret"})
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    scraper.close()


def test_ingest_and_http_metrics_move(super_admin_client):
    org, headers = _org(super_admin_client, "obs-metrics-t1")
    event = {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": "trc_m1",
        "span_id": "spn_m1",
        "timestamp": "2026-08-28T00:00:01Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "operation": "chat",
            "metadata": {"tenant_id": "obs-metrics-t1", "application_name": "app", "workflow_name": "wf"},
        },
    }
    assert org.post("/v1/events/batch", json={"events": [event]}, headers=headers).status_code == 200

    body = super_admin_client.get("/metrics").text
    assert 'norinth_ingest_events_total{tenant="obs-metrics-t1"} 1.0' in body
    assert 'norinth_ingest_batches_total{tenant="obs-metrics-t1"} 1.0' in body
    assert "norinth_http_requests_total" in body
    assert "norinth_http_request_duration_seconds_bucket" in body
    assert "norinth_audit_write_seconds_count" in body
    assert "norinth_outbox_pending" in body
    # route label is the template, not the raw path — cardinality stays bounded
    assert 'route="/v1/events/batch"' in body
    org.close()


def test_request_id_is_returned_and_propagates(super_admin_client):
    response = super_admin_client.get("/health")
    assert response.headers.get("x-request-id")

    echoed = super_admin_client.get("/health", headers={"X-Request-ID": "abc-123"})
    assert echoed.headers["x-request-id"] == "abc-123"

    # a hostile id is replaced, not reflected
    hostile = super_admin_client.get("/health", headers={"X-Request-ID": 'x"\r\nInjected: 1'})
    assert hostile.headers["x-request-id"] != 'x"\r\nInjected: 1'


def test_audit_appends_stream_to_the_log(super_admin_client, caplog):
    from app.storage.audit import record_audit

    with caplog.at_level(logging.INFO, logger="norinth.audit"):
        record_audit(actor_ref="ops@test", action="test.stream", tenant_id="acme")
    records = [r for r in caplog.records if r.name == "norinth.audit"]
    assert records, "audit append did not stream to the log"
    assert records[-1].action == "test.stream"
    assert records[-1].tenant_id == "acme"


def test_json_log_formatter_emits_parseable_lines():
    from app.services.observability import JsonLogFormatter, request_id_var

    formatter = JsonLogFormatter()
    token = request_id_var.set("req-42")
    try:
        record = logging.LogRecord("norinth.access", logging.INFO, __file__, 1, "request", (), None)
        record.status = 200
        record.duration_ms = 12.5
        line = json.loads(formatter.format(record))
    finally:
        request_id_var.reset(token)
    assert line["message"] == "request"
    assert line["request_id"] == "req-42"
    assert line["status"] == 200
    assert line["duration_ms"] == 12.5
    assert line["level"] == "INFO"


def test_metrics_render_is_valid_prometheus_shape():
    from app.services import observability

    observability.counter_inc("test_counter_total", "help text", {"label": 'quo"te'})
    observability.histogram_observe("test_hist_seconds", "help", 0.05)
    body = observability.render_metrics()
    assert "# TYPE test_counter_total counter" in body
    assert 'test_counter_total{label="quo\\"te"} 1.0' in body
    assert "# TYPE test_hist_seconds histogram" in body
    assert 'test_hist_seconds_bucket{le="+Inf"} 1' in body
    assert "test_hist_seconds_count 1" in body
