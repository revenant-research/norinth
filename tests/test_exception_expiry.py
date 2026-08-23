"""A risk exception expires: on/after its expires_at the waived finding reopens
(finding H6), and expires_at must be a future date.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_expired_exception_reopens_the_finding(fresh_db):
    from app.storage.raw_events import connect
    from app.storage.workflow import expire_due_exceptions

    with connect() as connection:
        connection.execute(
            "INSERT INTO risk_findings (finding_id, tenant_id, project, environment, application_name, rule_id, risk, severity, confidence, status, rationale, framework_refs, evidence_trace_ids, evidence_summary, evaluated_at) "
            "VALUES ('f1', 'acme', 'p', 'prod', 'A', 'r1', 'no guardrail', 'high', 0.9, 'waived', 'r', '[]', '[]', 's', 'x')"
        )
        connection.execute(
            "INSERT INTO governance_exceptions (exception_id, tenant_id, project, environment, application_name, target_type, target_id, reason, compensating_control, expires_at, status, actor_ref, created_at, updated_at) "
            "VALUES ('e1', 'acme', 'p', 'prod', 'A', 'risk_finding', 'f1', 'accepted', 'cc', '2000-01-01T00:00:00+00:00', 'active', 'u', 'x', 'x')"
        )

    assert expire_due_exceptions() == 1
    with connect() as connection:
        finding = connection.execute("SELECT status FROM risk_findings WHERE finding_id = 'f1'").fetchone()
        exc = connection.execute("SELECT status FROM governance_exceptions WHERE exception_id = 'e1'").fetchone()
    assert finding["status"] == "open"   # reopened
    assert exc["status"] == "expired"

    # A still-active exception (future expiry) is untouched.
    with connect() as connection:
        connection.execute("UPDATE risk_findings SET status = 'waived' WHERE finding_id = 'f1'")
        connection.execute("UPDATE governance_exceptions SET status = 'active', expires_at = '2999-01-01T00:00:00+00:00' WHERE exception_id = 'e1'")
    assert expire_due_exceptions() == 0
    with connect() as connection:
        assert connection.execute("SELECT status FROM risk_findings WHERE finding_id = 'f1'").fetchone()["status"] == "waived"


def test_exception_requires_a_future_date(super_admin_client):
    from app.api.routes import _validate_future_date
    from fastapi import HTTPException

    _validate_future_date("2999-01-01")  # ok
    for bad in ("2000-01-01", "not-a-date", ""):
        try:
            _validate_future_date(bad)
            raise AssertionError(f"expected rejection for {bad!r}")
        except HTTPException as error:
            assert error.status_code == 400
