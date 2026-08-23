"""Database backend abstraction: SQLite (default) or PostgreSQL.

SQLite is disqualifying for an enterprise evidence store (single writer, no
replication/HA, no network access — audit C-5 / buyer requirements). This module
lets the same storage code run on PostgreSQL by setting
``NORINTH_DATABASE_URL=postgresql://user:pass@host:port/dbname``; with it unset
the platform keeps the zero-config SQLite behaviour for local development.

The storage layer was written against the sqlite3 DB-API with a handful of
SQLite idioms. Rather than rewrite ~30 tables of SQL, this layer provides a
connection/cursor wrapper with the interface the code already uses and, for
PostgreSQL, translates those idioms at execution time:

    ?               -> %s            (positional placeholders)
    :name           -> %(name)s      (named placeholders)
    datetime('now') -> to_char(now() at time zone 'utc', 'YYYY-MM-DD HH24:MI:SS')
    INSERT OR IGNORE  -> INSERT ... ON CONFLICT DO NOTHING
    INSERT OR REPLACE -> INSERT ... ON CONFLICT (pk) DO UPDATE SET col=EXCLUDED.col
    INTEGER PRIMARY KEY AUTOINCREMENT -> BIGSERIAL PRIMARY KEY
    PRAGMA ...      -> no-op
    BEGIN IMMEDIATE -> BEGIN

Rows are dict-like on both backends (``row["col"]``, ``dict(row)``).
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "norinth.sqlite3"


def database_url() -> str | None:
    return os.getenv("NORINTH_DATABASE_URL") or None


def is_postgres() -> bool:
    url = database_url()
    return bool(url and url.startswith(("postgres://", "postgresql://")))


def database_path() -> Path:
    return Path(os.getenv("NORINTH_PLATFORM_DB", str(DEFAULT_DB_PATH)))


# Exceptions the storage layer catches for idempotent schema migrations
# (e.g. ALTER TABLE ADD COLUMN on a column that already exists).
try:  # pragma: no cover - import guard
    import psycopg  # type: ignore

    OperationalError: tuple[type[BaseException], ...] = (sqlite3.OperationalError, psycopg.Error)
    IntegrityError: tuple[type[BaseException], ...] = (sqlite3.IntegrityError, psycopg.errors.IntegrityError)
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore
    OperationalError = (sqlite3.OperationalError,)
    IntegrityError = (sqlite3.IntegrityError,)


# --- PostgreSQL SQL translation -------------------------------------------------

# Primary keys for tables written with INSERT OR REPLACE (needed to express the
# same upsert as ON CONFLICT ... DO UPDATE in PostgreSQL).
_REPLACE_PRIMARY_KEYS = {
    "control_assessments": "assessment_id",
    "governance_decisions": "decision_id",
    "governance_exceptions": "exception_id",
    "governance_observed_events": "entity_id",
    "risk_findings": "finding_id",
}

_NOW_TEXT = "to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')"
_NAMED_PARAM = re.compile(r"(?<![:\w'])[:]([a-zA-Z_]\w*)")
_REPLACE_RE = re.compile(r"INSERT OR REPLACE INTO\s+(\w+)\s*\(([^)]*)\)", re.IGNORECASE | re.DOTALL)


def _translate_replace(sql: str) -> str:
    match = _REPLACE_RE.search(sql)
    if not match:
        return sql
    table = match.group(1)
    columns = [column.strip() for column in match.group(2).split(",") if column.strip()]
    pk = _REPLACE_PRIMARY_KEYS.get(table)
    if pk is None:
        raise ValueError(f"INSERT OR REPLACE on table without a registered primary key: {table}")
    assignments = ", ".join(f"{column} = EXCLUDED.{column}" for column in columns if column != pk)
    head = sql[: match.start()] + f"INSERT INTO {table} ({', '.join(columns)})" + sql[match.end() :]
    return head.rstrip().rstrip(";") + f" ON CONFLICT ({pk}) DO UPDATE SET {assignments}"


def translate_sql(sql: str, params: Any = None) -> str:
    """Translate SQLite-flavoured SQL to PostgreSQL."""
    stripped = sql.lstrip()
    upper = stripped.upper()
    if upper.startswith("PRAGMA"):
        return ""
    if upper.startswith("BEGIN"):
        return "BEGIN"
    out = sql
    out = out.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    if upper.startswith("CREATE TABLE"):
        out = re.sub(r"\bREAL\b", "DOUBLE PRECISION", out)
    out = out.replace("datetime('now')", _NOW_TEXT)
    if "INSERT OR IGNORE" in out.upper():
        out = re.sub(r"INSERT OR IGNORE", "INSERT", out, flags=re.IGNORECASE)
        out = out.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    if "INSERT OR REPLACE" in out.upper():
        out = _translate_replace(out)
    if isinstance(params, dict):
        out = _NAMED_PARAM.sub(r"%(\1)s", out)
    else:
        out = out.replace("?", "%s")
    # PostgreSQL cannot infer the type of a bare parameter tested with IS NULL
    # ("could not determine data type of parameter"), a pattern the storage layer
    # uses for optional tenant scoping. Give such parameters an explicit type.
    out = re.sub(r"(%\([a-zA-Z_]\w*\)s|%s)(\s+IS\s+(?:NOT\s+)?NULL)", r"\1::text\2", out, flags=re.IGNORECASE)
    return out


# --- Connection wrappers ------------------------------------------------------


class _Cursor:
    def __init__(self, cursor, rowcount: int | None = None):
        self._cursor = cursor
        self._rowcount = rowcount

    def fetchone(self):
        return self._cursor.fetchone() if self._cursor is not None else None

    def fetchall(self):
        return self._cursor.fetchall() if self._cursor is not None else []

    @property
    def rowcount(self) -> int:
        if self._rowcount is not None:
            return self._rowcount
        return self._cursor.rowcount if self._cursor is not None else 0


class PostgresConnection:
    """Wrapper giving a psycopg connection the sqlite3-style interface the
    storage layer uses, with SQL translation.

    The underlying connection runs in autocommit mode and transactions are
    driven explicitly: ``with connect() as c:`` issues BEGIN on entry and
    COMMIT/ROLLBACK on exit (mirroring sqlite3's context manager), and code that
    runs ``connection.execute("BEGIN IMMEDIATE")`` ... ``COMMIT`` itself works
    unchanged because those statements pass straight through.
    """

    def __init__(self, raw):
        self._raw = raw
        self.isolation_level = None  # accepted for API compatibility

    def _in_transaction(self) -> bool:
        from psycopg.pq import TransactionStatus

        return self._raw.info.transaction_status != TransactionStatus.IDLE

    def execute(self, sql: str, params: Any = ()) -> _Cursor:
        translated = translate_sql(sql, params)
        if not translated:
            return _Cursor(None, rowcount=0)
        cursor = self._raw.cursor()
        upper = translated.lstrip().upper()
        is_txn_control = upper.startswith(("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE"))
        if is_txn_control or not self._in_transaction():
            cursor.execute(translated, params if params else None)
            return _Cursor(cursor)
        # SQLite has statement-level atomicity: a failed statement does not abort
        # the enclosing transaction, and the storage layer relies on that for its
        # idempotent try/except schema migrations (ALTER TABLE ADD COLUMN on an
        # existing column). PostgreSQL aborts the whole transaction on any error,
        # so wrap each statement in a savepoint and roll back to it on failure.
        self._raw.execute("SAVEPOINT norinth_stmt")
        try:
            cursor.execute(translated, params if params else None)
        except Exception:
            self._raw.execute("ROLLBACK TO SAVEPOINT norinth_stmt")
            raise
        finally:
            # Release only if the transaction is still healthy.
            from psycopg.pq import TransactionStatus

            if self._raw.info.transaction_status == TransactionStatus.INTRANS:
                self._raw.execute("RELEASE SAVEPOINT norinth_stmt")
        return _Cursor(cursor)

    def executemany(self, sql: str, seq_of_params: list[Any]) -> _Cursor:
        if not seq_of_params:
            return _Cursor(None, rowcount=0)
        translated = translate_sql(sql, seq_of_params[0])
        cursor = self._raw.cursor()
        cursor.executemany(translated, seq_of_params)
        return _Cursor(cursor)

    def commit(self) -> None:
        if self._in_transaction():
            self._raw.execute("COMMIT")

    def rollback(self) -> None:
        if self._in_transaction():
            self._raw.execute("ROLLBACK")

    def close(self) -> None:
        self._raw.close()

    def __enter__(self):
        if not self._in_transaction():
            self._raw.execute("BEGIN")
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self._raw.close()
        return False


class SqliteConnection:
    """Thin wrapper so the two backends expose the same object shape."""

    def __init__(self, raw: sqlite3.Connection):
        self._raw = raw

    @property
    def isolation_level(self):
        return self._raw.isolation_level

    @isolation_level.setter
    def isolation_level(self, value):
        self._raw.isolation_level = value

    def execute(self, sql: str, params: Any = ()) -> _Cursor:
        return _Cursor(self._raw.execute(sql, params))

    def executemany(self, sql: str, seq_of_params: list[Any]) -> _Cursor:
        return _Cursor(self._raw.executemany(sql, seq_of_params))

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        self._raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # Mirror sqlite3's context manager (commit/rollback), then close so we
        # do not leak file handles under load.
        try:
            if exc_type is None:
                self._raw.commit()
            else:
                self._raw.rollback()
        finally:
            self._raw.close()
        return False


# Fixed 64-bit key for the audit-chain advisory lock (arbitrary constant).
_AUDIT_LOCK_KEY = 4242000042420001


def serialize_writer(connection) -> None:
    """Serialize concurrent writers of an append-only chain across replicas.

    On PostgreSQL, SQLite's ``BEGIN IMMEDIATE`` write lock does not survive the
    translation to ``BEGIN`` (no lock under READ COMMITTED), so two workers can
    read the same tail and fork the chain. A transaction-scoped advisory lock
    restores single-writer ordering; it is released automatically at COMMIT.
    On SQLite the caller's ``BEGIN IMMEDIATE`` already holds the write lock.
    """
    if is_postgres():
        connection.execute(f"SELECT pg_advisory_xact_lock({_AUDIT_LOCK_KEY})")


def connect():
    """Open a connection to the configured backend."""
    if is_postgres():
        if psycopg is None:  # pragma: no cover
            raise RuntimeError("NORINTH_DATABASE_URL is set to PostgreSQL but psycopg is not installed")
        from psycopg.rows import dict_row

        raw = psycopg.connect(database_url(), row_factory=dict_row, autocommit=True)
        return PostgresConnection(raw)

    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(path, timeout=30)
    raw.row_factory = sqlite3.Row
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA busy_timeout=30000")
    return SqliteConnection(raw)
