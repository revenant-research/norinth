"""sqlite to postgres sql translation"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage.db import translate_sql  # noqa: E402


def test_positional_placeholders():
    assert translate_sql("SELECT * FROM t WHERE a = ? AND b = ?", ("x", "y")) == "SELECT * FROM t WHERE a = %s AND b = %s"


def test_named_placeholders():
    out = translate_sql("SELECT * FROM t WHERE a = :a LIMIT :limit", {"a": 1, "limit": 5})
    assert out == "SELECT * FROM t WHERE a = %(a)s LIMIT %(limit)s"


def test_datetime_now_becomes_text_timestamp():
    out = translate_sql("INSERT INTO t (ts) VALUES (datetime('now'))")
    assert "to_char" in out and "datetime('now')" not in out


def test_insert_or_ignore():
    out = translate_sql("INSERT OR IGNORE INTO t (a) VALUES (?)", ("x",))
    assert out.startswith("INSERT INTO t (a) VALUES (%s)")
    assert out.endswith("ON CONFLICT DO NOTHING")


def test_insert_or_replace_becomes_upsert_on_pk():
    out = translate_sql(
        "INSERT OR REPLACE INTO risk_findings (finding_id, name, signal) VALUES (?, ?, ?)",
        ("r", "n", "s"),
    )
    assert "INSERT INTO risk_findings (finding_id, name, signal)" in out
    assert "ON CONFLICT (finding_id) DO UPDATE SET name = EXCLUDED.name, signal = EXCLUDED.signal" in out


def test_insert_or_replace_unknown_table_is_an_error():
    import pytest

    with pytest.raises(ValueError):
        translate_sql("INSERT OR REPLACE INTO mystery (a) VALUES (?)", ("x",))


def test_autoincrement_and_real_in_ddl():
    out = translate_sql("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v REAL)")
    assert "BIGSERIAL PRIMARY KEY" in out
    assert "DOUBLE PRECISION" in out


def test_pragma_is_noop_and_begin_immediate_is_begin():
    assert translate_sql("PRAGMA journal_mode=WAL") == ""
    assert translate_sql("BEGIN IMMEDIATE") == "BEGIN"


def test_null_tested_parameter_gets_a_type():
    out = translate_sql("SELECT 1 WHERE (:t IS NULL AND c IS NULL) OR c = :t", {"t": None})
    assert "%(t)s::text IS NULL" in out
