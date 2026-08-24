"""framework coverage denominator comes from mapped controls, not assessed-only"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


@pytest.fixture
def org_client(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "a@acme.test",
            "admin_display_name": "Acme admin",
            "admin_password": "acme-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
    try:
        yield org
    finally:
        org.close()


def test_coverage_denominator_comes_from_the_library(org_client):
    result = org_client.get("/api/compliance/framework-coverage").json()
    assert "basis" in result
    coverage = {row["framework"]: row for row in result["framework_coverage"]}
    # library maps these families; each has a non-zero denominator even with
    # nothing ingested yet (nothing satisfied)
    assert coverage, "expected framework rows from the mapped control library"
    for family in ("NIST AI RMF", "SOC 2", "ISO/IEC 42001", "EU AI Act"):
        assert family in coverage, f"{family} missing from coverage"
        row = coverage[family]
        assert row["total_requirements"] >= 1
        # no satisfying assessments so coverage cannot be perfect
        assert row["coverage_pct"] < 100
        # every unsatisfied mapped requirement is a named gap
        assert len(row["gaps"]) == row["total_requirements"] - row["satisfied"]


def test_unsatisfied_requirements_are_named_as_gaps(org_client):
    result = org_client.get("/api/compliance/framework-coverage").json()
    soc2 = next(row for row in result["framework_coverage"] if row["framework"] == "SOC 2")
    # soc 2 maps more than one distinct requirement in the shipped library
    assert soc2["total_requirements"] >= 2
    assert all(ref.startswith("SOC 2") for ref in soc2["gaps"])
