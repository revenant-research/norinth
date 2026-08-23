"""Multi-replica safety: outbox claim exclusivity and migration locking (H11).

With more than one replica, every replica runs a delivery worker and runs
migrations at boot. Claiming must hand a row to exactly one worker, and applying
migrations must be idempotent so a second (or concurrent) run does no work.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_migrations_are_idempotent(client):
    from app.storage.migrations import pending_migrations, run_migrations

    # The app fixture has already booted and migrated; a second run applies none.
    assert run_migrations() == []
    assert pending_migrations() == []


def test_claim_hands_each_row_to_one_worker(client):
    from app.storage.notifications import claim_pending, enqueue
    from app.storage.raw_events import connect

    with connect() as connection:
        for i in range(6):
            enqueue(
                connection,
                tenant_id="acme",
                channel="webhook",
                event_type="test.event",
                target=f"https://example.test/{i}",
                subject=None,
                payload={"i": i},
            )

    first = claim_pending(limit=3, worker_id="worker-a")
    second = claim_pending(limit=3, worker_id="worker-b")

    ids_a = {row["id"] for row in first}
    ids_b = {row["id"] for row in second}
    assert len(ids_a) == 3
    assert len(ids_b) == 3
    # No row is ever claimed by both workers.
    assert ids_a.isdisjoint(ids_b)
    # Each claimed row is attributed to the worker that claimed it.
    assert all(row["claimed_by"] == "worker-a" for row in first)
    assert all(row["claimed_by"] == "worker-b" for row in second)


def test_claimed_rows_are_not_reclaimed(client):
    from app.storage.notifications import claim_pending, enqueue
    from app.storage.raw_events import connect

    with connect() as connection:
        enqueue(
            connection,
            tenant_id="acme",
            channel="webhook",
            event_type="test.event",
            target="https://example.test/only",
            subject=None,
            payload={},
        )
    first = claim_pending(limit=10, worker_id="w1")
    second = claim_pending(limit=10, worker_id="w2")
    assert len(first) == 1
    # The single row is already delivering; a second worker gets nothing.
    assert second == []
