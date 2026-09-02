"""a mid-fold failure must be recoverable, not a silent permanent evidence gap

ingest commits the raw event, then folds it into derived state in a dozen
independent steps. before the fold ledger, a failure between the commit and the
end of the fold left the event stored but never projected: the idempotent insert
meant the client's retry inserted nothing and the fold was skipped forever, so
the raw record said the event arrived while the evidence said it never happened.

these tests hold the fix: a fold step that raises leaves the row stored and
pending (folded_at NULL), a later fold — a client retry or the background sweeper
— completes it, and the one non-idempotent projection (the inventory increment)
runs exactly once across the failure and the recovery, so nothing double counts.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}
META = {"tenant_id": "acme", "application_name": "Claims", "workflow_name": "triage"}


def _model_call(span: str = "spn_r") -> dict:
    return {
        **BASE, "type": "model.call", "trace_id": f"trc_{span}", "span_id": span,
        "timestamp": "2026-08-22T00:00:00Z", "status": "success",
        "attributes": {"provider": "openai", "model": "gpt-4o",
                       "usage": {"input_tokens": 10, "output_tokens": 4}, "metadata": META},
    }


def _ingest_client(super_admin_client, *, raise_server_exceptions: bool = True):
    """an org with an ingestion key; returns (client, headers)"""
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={
        "tenant_id": "acme", "name": "Acme", "admin_email": "oa@acme.test",
        "admin_display_name": "OA", "admin_password": "oa-password-1"})
    org = TestClient(app, raise_server_exceptions=raise_server_exceptions)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, {"Authorization": f"Bearer {token}"}


def _row():
    """the single stored sdk_events row for acme, or None"""
    from app.storage.raw_events import connect

    with connect() as connection:
        rows = connection.execute(
            "SELECT id, folded_at, counted_at, fold_attempts FROM sdk_events WHERE tenant_id = 'acme'"
        ).fetchall()
    return [dict(r) for r in rows]


def _model_calls(org) -> int:
    apps = org.get("/api/applications").json()["applications"]
    return int(apps[0]["model_calls"]) if apps else 0


def test_failed_fold_leaves_the_event_stored_and_pending_not_lost(super_admin_client, monkeypatch):
    """the issue itself: a fold step raises after the raw insert has committed.

    the event must be stored (durable) and marked pending (folded_at NULL) — the
    ledger tracking that lets it be re-folded — never stored-and-silently-unfolded.
    """
    import app.storage.fold as fold

    org, h = _ingest_client(super_admin_client, raise_server_exceptions=False)

    def boom(_events):
        raise RuntimeError("fold step failed mid-batch")

    # a step that runs after the raw insert commits
    monkeypatch.setattr(fold, "fold_batch_fingerprints", boom)
    resp = org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h)
    assert resp.status_code == 500, resp.text  # the client learns the fold did not complete

    rows = _row()
    assert len(rows) == 1, "the raw event must be stored despite the fold failure"
    assert rows[0]["folded_at"] is None, "the row must be marked pending, not silently unfolded"
    assert rows[0]["fold_attempts"] >= 1, "the failed fold must be counted for visibility"
    org.close()


def test_client_retry_recovers_the_fold_without_double_counting(super_admin_client, monkeypatch):
    """process_events (the increment) runs, a later step fails, the client retries.

    the retry inserts nothing (dedup), but the row is still pending, so the fold
    re-runs and completes — and because process_events already counted the row,
    the retry does not count it again. model_calls stays 1.
    """
    import app.storage.fold as fold

    org, h = _ingest_client(super_admin_client, raise_server_exceptions=False)

    calls = {"n": 0}
    real = fold.fold_batch_fingerprints

    def fail_once(events):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient fold failure")
        return real(events)

    monkeypatch.setattr(fold, "fold_batch_fingerprints", fail_once)

    first = org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h)
    assert first.status_code == 500  # first fold failed at the fingerprint step

    rows = _row()
    assert rows[0]["folded_at"] is None, "still pending after the failed fold"
    assert rows[0]["counted_at"] is not None, "the increment projection committed before the failure"
    assert _model_calls(org) == 1, "the increment ran once on the first (failed) attempt"

    # the client retries the identical batch: insert dedups to nothing, but the
    # pending row is re-folded and this time the fingerprint step succeeds
    retry = org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h)
    assert retry.status_code == 200 and retry.json()["accepted"] == 0

    rows = _row()
    assert len(rows) == 1, "still one raw row"
    assert rows[0]["folded_at"] is not None, "the retry completed the fold"
    assert _model_calls(org) == 1, "exactly-once: the retry did not double count the increment"
    org.close()


def test_background_sweeper_recovers_a_client_that_never_retries(super_admin_client, monkeypatch):
    """the fold fails and the client never comes back. the sweeper folds the
    pending row on its own, so derived state still catches up to the raw record."""
    import app.storage.fold as fold

    org, h = _ingest_client(super_admin_client, raise_server_exceptions=False)

    real = fold.process_prompt_events

    def boom(_events):
        raise RuntimeError("fold step failed")

    monkeypatch.setattr(fold, "process_prompt_events", boom)
    assert org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h).status_code == 500
    assert _row()[0]["folded_at"] is None
    # the client is gone; no retry. restore the healthy step, then the sweeper runs
    # (restore only this attribute, not fresh_db's NORINTH_PLATFORM_DB monkeypatch)
    monkeypatch.setattr(fold, "process_prompt_events", real)

    from app.services.fold_sweeper import run_once

    result = run_once()
    assert result["folded"] == 1, result

    rows = _row()
    assert rows[0]["folded_at"] is not None, "the sweeper folded the orphaned pending row"
    assert _model_calls(org) == 1
    org.close()


def test_healthy_ingest_marks_rows_folded(super_admin_client):
    """the happy path still folds and marks done: no pending rows are left behind"""
    from app.storage.raw_events import count_unfolded

    org, h = _ingest_client(super_admin_client)
    assert org.post("/v1/events/batch", json={"events": [_model_call()]}, headers=h).status_code == 200
    assert count_unfolded("acme") == 0, "a healthy ingest leaves nothing pending"
    assert _row()[0]["folded_at"] is not None
    org.close()


def test_poison_row_is_isolated_and_quarantined_by_the_sweeper(super_admin_client, monkeypatch):
    """one row that can never fold must not block the rows queued with it, and
    must stop being retried forever once it exhausts the budget"""
    import app.storage.fold as fold

    org, h = _ingest_client(super_admin_client, raise_server_exceptions=False)

    # two rows land pending together; the whole-set fold fails on the second
    from app.storage.raw_events import insert_events

    good = _model_call("good")
    poison = _model_call("poison")
    # bind + store both directly as pending (bypass the request-path fold)
    for ev in (good, poison):
        ev["attributes"]["metadata"] = dict(META)
    insert_events([good, poison])

    real = fold.process_prompt_events

    def fail_on_poison(events):
        if any(e.get("span_id") == "poison" for e in events):
            raise RuntimeError("this row never folds")
        return real(events)

    monkeypatch.setattr(fold, "process_prompt_events", fail_on_poison)

    # the sweeper folds the set: whole-set fails, so it isolates row by row —
    # the good row folds, the poison row keeps failing and accrues attempts
    from app.services.fold_sweeper import run_once

    for _ in range(fold.max_attempts() + 1):
        run_once()

    by_span = {}
    from app.storage.raw_events import connect

    with connect() as connection:
        for r in connection.execute("SELECT span_id, folded_at, fold_attempts FROM sdk_events WHERE tenant_id='acme'").fetchall():
            by_span[r["span_id"]] = dict(r)

    assert by_span["good"]["folded_at"] is not None, "the good row folded despite the poison beside it"
    assert by_span["poison"]["folded_at"] is None, "the poison row stays pending"
    assert by_span["poison"]["fold_attempts"] >= fold.max_attempts(), "the poison row is quarantined after the budget"

    from app.storage.raw_events import count_quarantined

    assert count_quarantined(fold.max_attempts()) >= 1, "the quarantined row is visible to the gauge"
    org.close()
