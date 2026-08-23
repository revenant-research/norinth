"""Framework coverage is measured against mapped controls, not assessed-only (H8).

Previously the denominator was only the requirements that had produced an
assessment, so a single passing control showed 100% coverage of its framework.
The denominator is now every requirement the control library maps.
"""

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
    # The library maps these families; each must have a non-zero denominator even
    # though no events have been ingested (i.e. nothing is satisfied yet).
    assert coverage, "expected framework rows from the mapped control library"
    for family in ("NIST AI RMF", "SOC 2", "ISO/IEC 42001", "EU AI Act"):
        assert family in coverage, f"{family} missing from coverage"
        row = coverage[family]
        assert row["total_requirements"] >= 1
        # With no satisfying assessments, coverage cannot be a perfect score.
        assert row["coverage_pct"] < 100
        # Every mapped requirement with no satisfying assessment is a named gap.
        assert len(row["gaps"]) == row["total_requirements"] - row["satisfied"]


def test_unsatisfied_requirements_are_named_as_gaps(org_client):
    result = org_client.get("/api/compliance/framework-coverage").json()
    soc2 = next(row for row in result["framework_coverage"] if row["framework"] == "SOC 2")
    # SOC 2 maps more than one distinct requirement in the shipped library.
    assert soc2["total_requirements"] >= 2
    assert all(ref.startswith("SOC 2") for ref in soc2["gaps"])
