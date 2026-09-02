"""versioned schema-migration runner"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_fresh_database_has_all_migrations_applied(fresh_db):
    from app.storage.migrations import MIGRATIONS, applied_versions, pending_migrations

    applied = {row["version"] for row in applied_versions()}
    assert applied == {m.version for m in MIGRATIONS}
    assert pending_migrations() == []


def test_rerun_is_a_noop(fresh_db):
    from app.storage.migrations import run_migrations

    assert run_migrations() == []


def test_new_migration_applies_exactly_once(fresh_db, monkeypatch):
    import app.storage.migrations as migrations

    calls: list[int] = []

    def _0999(connection):
        calls.append(1)
        connection.execute("CREATE TABLE IF NOT EXISTS migration_probe (id INTEGER PRIMARY KEY)")

    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        [*migrations.MIGRATIONS, migrations.Migration(999, "probe", _0999)],
    )
    assert migrations.run_migrations() == [999]
    assert migrations.run_migrations() == []  # recorded, not re-applied
    assert calls == [1]

    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute("INSERT INTO migration_probe (id) VALUES (1)")
        assert connection.execute("SELECT COUNT(*) AS n FROM migration_probe").fetchone()["n"] == 1


def test_fold_ledger_backfills_existing_rows_as_folded(tmp_path, monkeypatch):
    """migration 23 must mark every pre-existing raw event folded and counted

    those rows were already projected by the pre-ledger code path. if the upgrade
    left them pending, the sweeper would re-fold all of history and double count
    every tenant's inventory — the exact failure the ledger exists to prevent.
    a row inserted after the migration must instead start pending.
    """
    monkeypatch.setenv("NORINTH_PLATFORM_DB", str(tmp_path / "pre23.sqlite3"))
    monkeypatch.delenv("NORINTH_DATABASE_URL", raising=False)

    from app.storage.migrations import _0023_fold_ledger
    from app.storage.raw_events import connect

    # a sdk_events table as it stood before the fold-ledger columns existed
    with connect() as connection:
        connection.execute(
            "CREATE TABLE sdk_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT, "
            "schema_version TEXT, trace_id TEXT, span_id TEXT, timestamp TEXT, service TEXT, "
            "environment TEXT, project TEXT, status TEXT, tenant_id TEXT, raw_event TEXT NOT NULL, "
            "ingested_at TEXT)"
        )
        connection.execute(
            "INSERT INTO sdk_events (event_type, schema_version, trace_id, span_id, timestamp, service, "
            "environment, project, status, tenant_id, raw_event, ingested_at) "
            "VALUES ('model.call', '2026-01', 't', 's', 'x', 'svc', 'prod', 'p1', 'success', 'acme', '{}', "
            "'2026-01-02T00:00:00Z')"
        )

    with connect() as connection:
        _0023_fold_ledger(connection)

    with connect() as connection:
        existing = dict(connection.execute("SELECT folded_at, counted_at, fold_attempts FROM sdk_events").fetchone())
    assert existing["folded_at"] is not None, "an existing row must be backfilled folded, never re-folded on upgrade"
    assert existing["counted_at"] is not None, "an existing row must be backfilled counted, never re-counted on upgrade"
    assert existing["fold_attempts"] == 0

    # a row inserted after the migration starts pending, so the fold picks it up
    with connect() as connection:
        connection.execute(
            "INSERT INTO sdk_events (event_type, schema_version, trace_id, span_id, timestamp, service, "
            "environment, project, status, tenant_id, raw_event) "
            "VALUES ('model.call', '2026-01', 't2', 's2', 'x', 'svc', 'prod', 'p1', 'success', 'acme', '{}')"
        )
        new = dict(connection.execute("SELECT folded_at, counted_at FROM sdk_events WHERE span_id = 's2'").fetchone())
    assert new["folded_at"] is None and new["counted_at"] is None, "a newly inserted row must start pending"

    # re-running the migration is a no-op (guarded by _has_column)
    with connect() as connection:
        _0023_fold_ledger(connection)


def test_schema_status_endpoint_is_super_admin_only(super_admin_client):
    resp = super_admin_client.get("/api/admin/schema")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backend"] in {"sqlite", "postgresql"}
    assert body["pending"] == []
    assert body["current_version"] >= 2
    assert any(row["version"] == 1 for row in body["applied"])
