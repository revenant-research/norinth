"""postgres connections are pooled, not dialed per storage call

per-request connection churn (tcp + auth + startup per query batch) was on
the eval's ops list. these tests run only under the postgres suite; sqlite
keeps per-call connections by design (cheap to open, thread-bound objects).
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage import db  # noqa: E402

postgres_only = pytest.mark.skipif(not db.is_postgres(), reason="pool applies to postgres only")


@postgres_only
def test_connections_are_reused(fresh_db):
    db.close_pg_pool()
    with db.connect() as connection:
        connection.execute("SELECT 1").fetchone()
        first_raw = connection._raw
    with db.connect() as connection:
        connection.execute("SELECT 1").fetchone()
        second_raw = connection._raw
    assert first_raw is second_raw, "a released connection was not reused"
    assert not first_raw.closed, "release closed the socket instead of pooling it"


@postgres_only
def test_release_rolls_back_a_stray_transaction(fresh_db):
    db.close_pg_pool()
    connection = db.connect()
    connection.execute("BEGIN")
    connection.execute("CREATE TABLE pool_probe (n INTEGER)")
    connection.execute("INSERT INTO pool_probe (n) VALUES (1)")
    # caller walks away mid-transaction (error paths do this via close())
    connection.close()

    with db.connect() as clean:
        # same raw connection, but the transaction must be gone with its writes
        from psycopg.pq import TransactionStatus

        row = clean._raw.info.transaction_status
        assert row in (TransactionStatus.IDLE, TransactionStatus.INTRANS)
        exists = clean.execute(
            "SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_name = 'pool_probe'"
        ).fetchone()
        assert exists["n"] == 0, "a stray transaction leaked into the next caller"


@postgres_only
def test_pool_size_zero_restores_dial_per_call(fresh_db, monkeypatch):
    monkeypatch.setenv("NORINTH_PG_POOL_SIZE", "0")
    db.close_pg_pool()
    with db.connect() as connection:
        first_raw = connection._raw
    assert first_raw.closed, "with pooling disabled, release must close the socket"
    with db.connect() as connection:
        assert connection._raw is not first_raw


@postgres_only
def test_pool_never_exceeds_its_cap(fresh_db, monkeypatch):
    monkeypatch.setenv("NORINTH_PG_POOL_SIZE", "2")
    db.close_pg_pool()
    connections = [db.connect() for _ in range(4)]
    for connection in connections:
        connection.execute("SELECT 1").fetchone()
        connection.close()
    assert len(db._pg_pool) <= 2
    db.close_pg_pool()


@postgres_only
def test_stale_idle_connections_are_discarded(fresh_db, monkeypatch):
    db.close_pg_pool()
    with db.connect() as connection:
        first_raw = connection._raw
    monkeypatch.setenv("NORINTH_PG_POOL_MAX_IDLE_SECONDS", "0")
    with db.connect() as connection:
        assert connection._raw is not first_raw, "an aged-out connection was handed back out"
    db.close_pg_pool()
