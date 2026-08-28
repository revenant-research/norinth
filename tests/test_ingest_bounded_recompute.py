"""ingest cost must not grow with stored history

the recompute after every batch read — and with encryption on, decrypted —
each touched application's entire event history, twice (fingerprints and
assessments). the cost of accepting one event grew with every successful
day. flagged as an SLA blocker in the F500 buyer evaluation. the request
path now folds the batch into derived state at O(batch); the full refresh
functions remain as the rebuild path.
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime, timedelta

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


def _event(tenant: str, span: str, *, event_type: str = "model.call", minutes_ago: int = 60, **attrs) -> dict:
    base_attrs: dict = {"metadata": {"tenant_id": tenant, "application_name": f"{tenant}-app", "workflow_name": "wf"}}
    if event_type == "model.call":
        base_attrs.update({"provider": "openai", "model": "gpt-4o", "operation": "chat",
                           "usage": {"input_tokens": 1, "output_tokens": 1}})
    base_attrs.update(attrs)
    return {
        "type": event_type,
        "schema_version": "2026-01",
        "trace_id": f"trc_{span}",
        "span_id": f"spn_{span}",
        "timestamp": (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat(),
        "service": "svc",
        "environment": "prod",
        "project": "p1",
        "attributes": base_attrs,
    }


def test_ingest_does_not_reread_or_decrypt_history(super_admin_client, monkeypatch):
    """the defect itself: with N stored events, accepting one more must not
    deserialize N raw bodies. counted at the seam every history read passes
    through (lifecycle.list_application_events -> deserialize_raw_event)."""
    import app.storage.lifecycle as lifecycle

    org, headers = _org(super_admin_client, "acme")
    seed = [_event("acme", f"s{i}", minutes_ago=120 - i) for i in range(60)]
    assert org.post("/v1/events/batch", json={"events": seed}, headers=headers).status_code == 200

    calls = {"n": 0}
    real = lifecycle.deserialize_raw_event

    def counting(payload):
        calls["n"] += 1
        return real(payload)

    monkeypatch.setattr(lifecycle, "deserialize_raw_event", counting)
    assert org.post("/v1/events/batch", json={"events": [_event("acme", "one-more", minutes_ago=1)]}, headers=headers).status_code == 200
    assert calls["n"] == 0, f"ingest re-read {calls['n']} stored raw events for a one-event batch"
    org.close()


def test_fold_result_is_a_fixed_point_of_the_full_recompute(super_admin_client):
    """the equivalence claim, checked directly: after folding several batches,
    a full-history recompute must not change any fingerprint, assessment, or
    finding — and must not raise a single new material change."""
    from app.storage.governance_policy import refresh_governance_assessments
    from app.storage.lifecycle import refresh_lifecycle_state
    from app.storage.raw_events import connect

    org, headers = _org(super_admin_client, "beta")
    batches = [
        [_event("beta", "m1", minutes_ago=50)],
        [_event("beta", "m2", minutes_ago=40, model="claude-sonnet-5", provider="anthropic"),
         _event("beta", "g1", event_type="guardrail.decision", minutes_ago=39,
                guardrail_name="pii", decision="allow", matched_rules=["r1"])],
        [_event("beta", "e1", event_type="eval.result", minutes_ago=20,
                eval_name="safety", score=0.9, threshold=0.5, passed=True),
         _event("beta", "err1", minutes_ago=10) | {"status": "error"}],
    ]
    for batch in batches:
        assert org.post("/v1/events/batch", json={"events": batch}, headers=headers).status_code == 200

    def snapshot():
        with connect() as connection:
            fingerprints = {
                row["fingerprint_id"]: (row["fingerprint_hash"], row["fingerprint_payload"])
                for row in connection.execute("SELECT * FROM lifecycle_fingerprints").fetchall()
            }
            assessments = {
                row["assessment_id"]: (row["status"], row["evidence_trace_ids"])
                for row in connection.execute("SELECT * FROM control_assessments").fetchall()
            }
            findings = {
                row["finding_id"]: (row["status"], row["evidence_summary"])
                for row in connection.execute("SELECT * FROM risk_findings").fetchall()
            }
            changes = connection.execute("SELECT COUNT(*) AS n FROM change_events").fetchone()["n"]
        return fingerprints, assessments, findings, changes

    folded_fp, folded_assess, folded_findings, folded_changes = snapshot()
    assert folded_fp, "fold produced no fingerprints"
    assert folded_findings, "fold produced no findings"

    # the full recompute over all history must agree with the folded state
    refresh_lifecycle_state()
    refresh_governance_assessments()
    full_fp, full_assess, full_findings, full_changes = snapshot()

    assert full_fp == folded_fp, "full recompute changed a fingerprint the fold produced"
    assert {k: v[0] for k, v in full_assess.items()} == {k: v[0] for k, v in folded_assess.items()}
    assert {k: v for k, v in full_findings.items()} == folded_findings
    assert full_changes == folded_changes, "full recompute raised a material change the fold missed"
    org.close()


def test_new_model_still_raises_a_material_change_through_the_fold(super_admin_client):
    org, headers = _org(super_admin_client, "gamma")
    assert org.post("/v1/events/batch", json={"events": [_event("gamma", "m1", minutes_ago=30)]}, headers=headers).status_code == 200
    before = org.get("/api/change-events").json()["changes"]

    swapped = _event("gamma", "m2", minutes_ago=5, model="grok-simulacrum-9", provider="xai")
    assert org.post("/v1/events/batch", json={"events": [swapped]}, headers=headers).status_code == 200
    after = org.get("/api/change-events").json()["changes"]
    assert len(after) > len(before), "a new provider/model must still raise a material change"
    org.close()


def test_guardrail_arriving_later_still_satisfies_its_control(super_admin_client):
    """monotone persistence: evidence in a later batch upgrades the assessment"""
    org, headers = _org(super_admin_client, "delta")
    assert org.post("/v1/events/batch", json={"events": [_event("delta", "m1", minutes_ago=30)]}, headers=headers).status_code == 200

    controls = {c["control_id"]: c for c in org.get("/api/control-evidence").json()["controls"]}
    assert controls["AI-GRD-001"]["status"] == "missing"

    guardrail = _event("delta", "g1", event_type="guardrail.decision", minutes_ago=5,
                       guardrail_name="pii", decision="allow", matched_rules=["r1"])
    assert org.post("/v1/events/batch", json={"events": [guardrail]}, headers=headers).status_code == 200
    controls = {c["control_id"]: c for c in org.get("/api/control-evidence").json()["controls"]}
    assert controls["AI-GRD-001"]["status"] == "passing"
    org.close()


def test_repeat_usage_of_a_known_model_is_not_a_material_change(super_admin_client):
    """the fold work surfaced this: fingerprint payload entries are label sets,
    but models/eval_thresholds were built without dedup, so a SECOND call of an
    already-known model appended a duplicate entry and ordinary repeat usage
    read as a material change (which blocks release gates)."""
    org, headers = _org(super_admin_client, "epsilon")
    assert org.post("/v1/events/batch", json={"events": [_event("epsilon", "m1", minutes_ago=30)]}, headers=headers).status_code == 200
    before = org.get("/api/change-events").json()["changes"]

    # same provider, same model, new trace: routine traffic
    assert org.post("/v1/events/batch", json={"events": [_event("epsilon", "m2", minutes_ago=5)]}, headers=headers).status_code == 200
    after = org.get("/api/change-events").json()["changes"]
    assert len(after) == len(before), "repeat usage of a known model raised a material change"
    org.close()
