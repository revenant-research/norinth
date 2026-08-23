"""Regression test for atomic set-merge on inventory entities (audit H-11).

The application/model/provider inventory rows accumulate JSON sets across ingest
batches via a read-modify-write. This verifies the sets accumulate correctly
(the transaction change did not break merging) and that a second batch's members
are not lost.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _model_call(provider: str, span: str) -> dict:
    return {
        "type": "model.call",
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": {
            "provider": provider,
            "model": f"{provider}-model",
            "operation": "chat",
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "metadata": {"tenant_id": "tenant-local", "application_name": "app", "workflow_name": "wf"},
        },
    }


def _ingest(client, event):
    return client.post("/v1/events/batch", json={"events": [event]}, headers={"Authorization": "Bearer dev"})


def test_merge_sets_unit_accumulates():
    from app.storage.entities import merge_sets

    # First observation.
    first = merge_sets(None, {"providers": "openai"})
    assert first["providers"] == ["openai"]

    # Second observation on an existing row keeps the old member and adds the new.
    class _Row(dict):
        def __getitem__(self, key):
            return super().__getitem__(key)

    row = _Row({"providers": '["openai"]'})
    second = merge_sets(row, {"providers": "anthropic"})
    assert second["providers"] == ["anthropic", "openai"]


def test_two_batches_accumulate_providers(client):
    # Two separate ingest batches for the same application, different providers.
    assert _ingest(client, _model_call("openai", "a")).status_code == 200
    assert _ingest(client, _model_call("anthropic", "b")).status_code == 200

    from app.storage.entities import decode_json
    from app.storage.raw_events import connect

    with connect() as connection:
        row = connection.execute(
            "SELECT providers FROM governance_applications WHERE application_name = 'app'"
        ).fetchone()
    providers = set(decode_json(row["providers"], []))
    # Neither provider was lost across the two batches.
    assert providers == {"openai", "anthropic"}
