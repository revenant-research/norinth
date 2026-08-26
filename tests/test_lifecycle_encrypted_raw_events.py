"""material-change detection must work when raw events are encrypted at rest

with NORINTH_ENCRYPT_RAW_EVENTS=1 the raw_event column is ciphertext. lifecycle
fingerprinting must decrypt it; a plain json decode would yield {} for every row
and silently detect no changes, leaving release-gate material-change evidence
incomplete.
"""

from __future__ import annotations

from tests.helpers import login_and_activate

META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def _model_call(model: str, span: str) -> dict:
    return {
        "type": "model.call", "schema_version": "2026-01", "trace_id": f"t_{span}", "span_id": span,
        "timestamp": "2026-08-22T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
        "attributes": {"provider": "openai", "model": model, "usage": {"input_tokens": 1, "output_tokens": 1}, "metadata": META},
    }


def test_material_change_detected_with_encrypted_raw_events(super_admin_client, monkeypatch):
    monkeypatch.setenv("NORINTH_ENCRYPT_RAW_EVENTS", "1")  # conftest already sets NORINTH_SECRET_KEY

    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
        "admin_display_name": "OA", "admin_password": "oa-password-1"})
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    # baseline model surface, then a change to it
    assert org.post("/v1/events/batch", json={"events": [_model_call("gpt-4o", "s1")]}, headers=h).status_code == 200
    assert org.post("/v1/events/batch", json={"events": [_model_call("gpt-4o-mini", "s2")]}, headers=h).status_code == 200

    with connect() as connection:
        # premise: the raw events really are encrypted at rest
        raw = connection.execute("SELECT raw_event FROM sdk_events LIMIT 1").fetchone()["raw_event"]
        assert raw.startswith("enc:v2:"), raw[:16]
        # the model change was detected despite the ciphertext
        changes = connection.execute(
            "SELECT COUNT(*) AS n FROM change_events WHERE status = 'open' AND application_name = 'Claims'"
        ).fetchone()["n"]
    assert changes >= 1, "encrypted raw events must not disable material-change detection"

    org.close()
