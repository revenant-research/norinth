"""governance decisions and exceptions are append-only records

record_decision and create_exception used INSERT OR REPLACE. the id is
content-derived, so only an identical resubmission collided — but that
resubmission rewrote created_at (falsifying when the decision was made as
evidence) and reset a lapsed exception back to 'active'. an audit-grade
record must not move once written.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _seed_finding(finding_id: str) -> None:
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO risk_findings (
                finding_id, tenant_id, project, environment, application_name, rule_id,
                risk, severity, status, rationale, framework_refs, evidence_trace_ids,
                evidence_summary, evaluated_at
            )
            VALUES (?, 'acme', 'p1', 'prod', 'app', 'rule-1', 'risk', 'high', 'open',
                    'seed', '[]', '[]', '{}', datetime('now'))
            """,
            (finding_id,),
        )


def _backdate(table: str, id_column: str, record_id: str, timestamp: str) -> None:
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(
            f"UPDATE {table} SET created_at = ? WHERE {id_column} = ?",  # noqa: S608
            (timestamp, record_id),
        )


def test_identical_decision_resubmission_does_not_move_created_at(fresh_db):
    from app.storage.workflow import record_decision

    _seed_finding("rf-1")
    first = record_decision("risk_finding", "rf-1", "accept", "acceptable for launch", "gov@acme.test")
    _backdate("governance_decisions", "decision_id", first["decision_id"], "2026-01-01 00:00:00")

    replay = record_decision("risk_finding", "rf-1", "accept", "acceptable for launch", "gov@acme.test")
    assert replay["decision_id"] == first["decision_id"]
    assert replay["created_at"] == "2026-01-01 00:00:00", "resubmission rewrote the decision timestamp"


def test_changed_decision_is_a_new_row_not_an_overwrite(fresh_db):
    from app.storage.raw_events import connect
    from app.storage.workflow import record_decision

    _seed_finding("rf-2")
    first = record_decision("risk_finding", "rf-2", "accept", "fine for now", "gov@acme.test")
    second = record_decision("risk_finding", "rf-2", "reject", "changed our mind", "gov@acme.test")
    assert first["decision_id"] != second["decision_id"]

    with connect() as connection:
        rows = connection.execute(
            "SELECT COUNT(*) AS n FROM governance_decisions WHERE target_id = ?", ("rf-2",)
        ).fetchone()
    assert rows["n"] == 2, "decision history must accumulate, not overwrite"


def test_replaying_an_identical_exception_does_not_resurrect_it(fresh_db):
    from app.storage.raw_events import connect
    from app.storage.workflow import create_exception

    _seed_finding("rf-3")
    first = create_exception(
        "risk_finding", "rf-3", "temporary waiver", "manual review", "2026-02-01T00:00:00+00:00", "gov@acme.test"
    )
    with connect() as connection:
        connection.execute(
            "UPDATE governance_exceptions SET status = 'lapsed' WHERE exception_id = ?",
            (first["exception_id"],),
        )
    _backdate("governance_exceptions", "exception_id", first["exception_id"], "2026-01-01 00:00:00")

    replay = create_exception(
        "risk_finding", "rf-3", "temporary waiver", "manual review", "2026-02-01T00:00:00+00:00", "gov@acme.test"
    )
    assert replay["exception_id"] == first["exception_id"]
    assert replay["status"] == "lapsed", "replaying an identical exception resurrected it to active"
    assert replay["created_at"] == "2026-01-01 00:00:00"


def test_new_expiry_is_a_new_exception(fresh_db):
    from app.storage.workflow import create_exception

    _seed_finding("rf-4")
    first = create_exception(
        "risk_finding", "rf-4", "waiver", "control", "2026-02-01T00:00:00+00:00", "gov@acme.test"
    )
    renewed = create_exception(
        "risk_finding", "rf-4", "waiver", "control", "2026-03-01T00:00:00+00:00", "gov@acme.test"
    )
    assert renewed["exception_id"] != first["exception_id"]
    assert renewed["status"] == "active"
