"""the tenancy boundary in the schema matches the one SECURITY.md documents

isolation here is logical: one database, one secret keyring, one audit chain, and
application code keeping tenants apart. that only holds if every table carrying
tenant data actually has a tenant column, so a new table joining the global set
should be a deliberate, reviewed act rather than something noticed in an audit.
the allowlist below is the documented exception list -- adding to it means
updating the "Security model" section of SECURITY.md too
"""

from __future__ import annotations

import pathlib

# global by design, each for a stated reason
GLOBAL_TABLES = {
    # what a role may do is platform-wide; who holds it (role_assignments) is per
    # tenant. a subsidiary needing different rules runs its own install
    "permissions",
    "role_permissions",
    # bound to a user, and the user is tenant-scoped
    "sessions",
    # brute-force counter keyed by login subject
    "login_throttle",
    # schema infrastructure
    "schema_migrations",
}

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _tables_and_columns(connection, postgres: bool) -> dict[str, list[str]]:
    if postgres:
        rows = connection.execute(
            "SELECT table_name AS name, column_name AS column FROM information_schema.columns "
            "WHERE table_schema = 'public' ORDER BY table_name"
        ).fetchall()
        schema: dict[str, list[str]] = {}
        for row in rows:
            schema.setdefault(row["name"], []).append(row["column"])
        return schema
    names = [
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    ]
    return {
        name: [row[1] for row in connection.execute(f'PRAGMA table_info("{name}")').fetchall()]
        for name in names
    }


def test_every_table_is_tenant_scoped_or_a_documented_exception(client):
    from app.storage.db import connect, is_postgres

    with connect() as connection:
        schema = _tables_and_columns(connection, is_postgres())

    assert schema, "no tables found"
    unscoped = {
        table
        for table, columns in schema.items()
        if table not in GLOBAL_TABLES and not {"tenant_id", "org_id"} & set(columns)
    }
    assert not unscoped, (
        f"table(s) carry no tenant column and are not documented as global: {sorted(unscoped)}. "
        "Add a tenant column, or add it to GLOBAL_TABLES here and to SECURITY.md."
    )


def test_the_global_allowlist_has_not_gone_stale(client):
    """an entry that no longer exists, or has since gained a tenant column, should be removed"""
    from app.storage.db import connect, is_postgres

    with connect() as connection:
        schema = _tables_and_columns(connection, is_postgres())

    for table in GLOBAL_TABLES:
        assert table in schema, f"{table} is allowlisted as global but no longer exists"
        assert not {"tenant_id", "org_id"} & set(schema[table]), (
            f"{table} is now tenant-scoped; drop it from GLOBAL_TABLES"
        )


def test_security_md_documents_the_logical_isolation_boundary():
    """the claim and the schema are reviewed together, so they cannot drift apart quietly"""
    security = (REPO_ROOT / "SECURITY.md").read_text()
    assert "Isolation is logical, not physical" in security
    assert "Role definitions are platform-wide" in security
    assert "audit chain is global" in security.lower()
