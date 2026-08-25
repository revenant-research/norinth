"""integrity holds under concurrent writers

a governance platform runs multiple workers and receives duplicate telemetry
(the SDK is at-least-once and retries), so these invariants must survive a race,
not just serial calls. both assertions are timing-independent — a lost write or
a forked chain or a double-counted event fails regardless of scheduling — so
they are stable on SQLite (WAL + busy_timeout serialize) and PostgreSQL (the
audit advisory lock and the unique dedup index serialize).
"""

from __future__ import annotations

import concurrent.futures as cf

from tests.helpers import login_and_activate


def test_audit_chain_survives_concurrent_writers(fresh_db):
    from app.storage.audit import record_audit, verify_audit_chain

    threads, per_thread = 8, 20

    def worker(t: int) -> None:
        for i in range(per_thread):
            record_audit(actor_ref=f"t{t}", action="concurrent.write", tenant_id="acme",
                         target_type="thing", target_id=f"{t}-{i}", detail={"t": t, "i": i})

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(worker, range(threads)))

    result = verify_audit_chain()
    assert result["entries"] == threads * per_thread, f"lost writes: {result['entries']}"
    assert result["ok"] is True, f"chain forked at {result.get('broken_at')}"


def test_duplicate_delivery_is_deduped_under_concurrency(super_admin_client):
    """the SDK retries, so the platform receives the same batch more than once,
    sometimes concurrently; it must store the event and its entities exactly once"""
    from app.main import app
    from app.storage.raw_events import connect
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={"tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
              "admin_display_name": "OA", "admin_password": "oa-password-1"},
    )
    with TestClient(app) as org:
        login_and_activate(org, "oa@acme.test", "oa-password-1")
        token = org.post("/api/ingestion-keys", json={"name": "ci"}).json()["token"]

    meta = {"tenant_id": "acme", "application_name": "App", "workflow_name": "wf"}
    batch = {"events": [{
        "type": "model.call", "schema_version": "2026-01", "trace_id": "dup-trace", "span_id": "dup-span",
        "timestamp": "2026-08-24T00:00:00Z", "service": "svc", "environment": "prod", "project": "p1",
        "status": "success",
        "attributes": {"provider": "openai", "model": "gpt-4o", "usage": {"input_tokens": 5, "output_tokens": 5},
                       "metadata": meta},
    }]}

    def send(_: int) -> int:
        client = TestClient(app)
        return client.post("/v1/events/batch", json=batch,
                           headers={"Authorization": f"Bearer {token}"}).status_code

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(send, range(8)))
    assert set(codes) == {200}, codes

    with connect() as connection:
        events = connection.execute(
            "SELECT COUNT(*) AS n FROM sdk_events WHERE trace_id = 'dup-trace' AND span_id = 'dup-span'"
        ).fetchone()["n"]
        models = connection.execute(
            "SELECT COUNT(*) AS n FROM governance_models WHERE tenant_id = 'acme'"
        ).fetchone()["n"]
        apps = connection.execute(
            "SELECT COUNT(*) AS n FROM governance_applications WHERE tenant_id = 'acme'"
        ).fetchone()["n"]
    assert events == 1, f"dedup race stored {events} copies of the event"
    assert models == 1 and apps == 1, "the race created duplicate governance entities"
