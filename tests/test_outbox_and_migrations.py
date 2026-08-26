"""outbox claim exclusivity and idempotent migrations across replicas"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_claim_uses_the_db_clock_not_the_app_clock(client, monkeypatch):
    """a delivery worker must claim due rows on the db server's clock

    next_attempt_at is written with the server clock (SQL datetime('now')). If the
    claim compared it against this process's clock instead, an app host whose
    clock lagged the db server would skip due rows. Simulate that lag and assert
    the rows are still claimed.
    """
    import datetime as real_datetime

    from app.storage import notifications as store
    from app.storage.notifications import claim_pending, enqueue
    from app.storage.raw_events import connect

    class LaggingClock(real_datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            # this process believes it is an hour behind the db server
            return real_datetime.datetime.now(tz) - real_datetime.timedelta(hours=1)

    monkeypatch.setattr(store, "datetime", LaggingClock)

    with connect() as connection:
        for i in range(3):
            enqueue(connection, tenant_id="acme", channel="webhook", event_type="test.event",
                    target=f"https://example.test/{i}", subject=None, payload={"i": i})

    claimed = claim_pending(limit=10, worker_id="worker-a")
    assert len(claimed) == 3, "due rows must be claimed on the server clock despite the lagging app clock"


def test_migrations_are_idempotent(client):
    from app.storage.migrations import pending_migrations, run_migrations

    # app fixture already booted and migrated; a second run applies none
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
    # no row is ever claimed by both workers
    assert ids_a.isdisjoint(ids_b)
    # each claimed row is attributed to the worker that claimed it
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
    # single row is already delivering; a second worker gets nothing
    assert second == []
