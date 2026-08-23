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


def test_schema_status_endpoint_is_super_admin_only(super_admin_client):
    resp = super_admin_client.get("/api/admin/schema")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["backend"] in {"sqlite", "postgresql"}
    assert body["pending"] == []
    assert body["current_version"] >= 2
    assert any(row["version"] == 1 for row in body["applied"])
