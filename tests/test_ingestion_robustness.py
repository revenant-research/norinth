"""Regression tests for ingestion robustness (audit C-6, C-3).

- Malformed events (missing required attributes) are rejected with 422 before
  any write, instead of crashing the pipeline with a 500 after a partial insert.
- Retried batches are idempotent (deduped by trace_id/span_id), so counters are
  not double-incremented.
- The database runs in WAL mode with a busy timeout for concurrency.
"""

from __future__ import annotations

HEADERS = {"Authorization": "Bearer dev"}


def _model_call(span_id="spn_a", trace_id="trc_a") -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": trace_id,
        "span_id": span_id,
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": "openai",
            "model": "gpt-4o",
            "operation": "chat",
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "metadata": {"tenant_id": "tenant-local", "application_name": "App", "workflow_name": "wf"},
        },
    }


def test_incomplete_prompt_event_is_422_not_500(client):
    # prompt.event without artifact_ref previously crashed ingestion (KeyError -> 500).
    event = {
        "type": "prompt.event",
        "schema_version": "2026-01",
        "trace_id": "trc_p",
        "span_id": "spn_p",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "prompt_id": "pr1",
            "version": "v1",
            # artifact_ref intentionally omitted
            "metadata": {"tenant_id": "tenant-local", "application_name": "App", "workflow_name": "wf"},
        },
    }
    resp = client.post("/v1/events/batch", json={"events": [event]}, headers=HEADERS)
    assert resp.status_code == 422, resp.text
    assert "artifact_ref" in resp.json()["detail"]


def test_malformed_batch_writes_nothing(client):
    # A batch with one good and one malformed event is rejected atomically:
    # nothing is persisted.
    good = _model_call()
    bad = {
        "type": "deployment.event",
        "schema_version": "2026-01",
        "trace_id": "trc_d",
        "span_id": "spn_d",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {"deployment_id": "d1", "metadata": {"tenant_id": "tenant-local"}},  # missing version, artifact_ref
    }
    resp = client.post("/v1/events/batch", json={"events": [good, bad]}, headers=HEADERS)
    assert resp.status_code == 422, resp.text

    from app.storage.raw_events import count_events

    assert count_events() == 0


def test_retried_batch_is_idempotent(client):
    batch = {"events": [_model_call(span_id="spn_dup", trace_id="trc_dup")]}
    first = client.post("/v1/events/batch", json=batch, headers=HEADERS)
    assert first.json()["accepted"] == 1

    second = client.post("/v1/events/batch", json=batch, headers=HEADERS)
    # The same span is ignored the second time; not double-counted.
    assert second.json()["accepted"] == 0

    from app.storage.raw_events import count_events

    assert count_events() == 1


def test_database_uses_wal(client):
    from app.storage.raw_events import connect

    with connect() as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
