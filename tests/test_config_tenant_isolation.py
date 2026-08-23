"""tenant config customizations stay isolated; platform defaults shared and immutable"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": tenant, "name": tenant, "admin_email": f"a@{tenant}.test", "admin_display_name": "A", "admin_password": f"{tenant}-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    return org


def test_config_customizations_are_tenant_isolated(super_admin_client):
    acme = _org(super_admin_client, "acme")
    beta = _org(super_admin_client, "beta")

    # both start from the same platform-default controls
    acme_default = {c["control_id"] for c in acme.get("/api/control-catalog").json()["controls"]}
    beta_default = {c["control_id"] for c in beta.get("/api/control-catalog").json()["controls"]}
    assert acme_default and acme_default == beta_default
    sample = sorted(acme_default)[0]

    # acme overrides a control and adds a new one
    assert acme.post("/api/control-catalog", json={"control_id": sample, "name": "ACME override", "evidence_event_types": ["model.call"], "required_fields": ["x"], "rationale": "r"}).status_code == 200
    assert acme.post("/api/control-catalog", json={"control_id": "ACME-ONLY", "name": "Acme only", "evidence_event_types": ["model.call"], "required_fields": [], "rationale": "r"}).status_code == 200

    acme_controls = {c["control_id"]: c for c in acme.get("/api/control-catalog").json()["controls"]}
    beta_controls = {c["control_id"]: c for c in beta.get("/api/control-catalog").json()["controls"]}
    assert acme_controls[sample]["name"] == "ACME override"       # acme sees its override
    assert "ACME-ONLY" in acme_controls
    assert beta_controls[sample]["name"] != "ACME override"       # beta still sees the default
    assert "ACME-ONLY" not in beta_controls                        # beta never sees acme's control

    # risk rules: acme downgrades a rule, beta unaffected
    beta_rules_before = {r["rule_id"]: r for r in beta.get("/api/risk-rules").json()["risk_rules"]}
    a_rule = sorted(beta_rules_before)[0]
    assert acme.post("/api/risk-rules", json={"rule_id": a_rule, "name": "downgraded", "signal": beta_rules_before[a_rule]["signal"], "severity": "low", "confidence": 0.1, "framework_refs": [], "rationale": "r"}).status_code == 200
    beta_rules_after = {r["rule_id"]: r for r in beta.get("/api/risk-rules").json()["risk_rules"]}
    assert beta_rules_after[a_rule]["severity"] == beta_rules_before[a_rule]["severity"]  # beta unchanged

    # review routing and owner policies: acme's change stays in acme
    assert acme.post("/api/review-queue-policies", json={"policy_id": "intake", "task_type": "intake_review", "assigned_role": "org_admin", "due_days": 1, "escalation_days": 1}).status_code == 200
    assert acme.post("/api/owner-policies", json={"policy_id": "p1", "subject_type": "application", "owner_role": "business_owner"}).status_code == 200

    # super admins cannot write config
    assert super_admin_client.post("/api/control-catalog", json={"control_id": "X", "name": "n", "evidence_event_types": ["model.call"], "required_fields": [], "rationale": "r"}).status_code == 403
    acme.close()
    beta.close()


@pytest.mark.skipif(bool(os.environ.get("NORINTH_TEST_DATABASE_URL")), reason="uses a throwaway SQLite file")
def test_migration_9_upgrades_populated_config_tables():
    """migration 9 upgrades single-column config tables to composite tenant key"""
    import os
    import tempfile

    from app.storage import db

    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    os.environ["NORINTH_PLATFORM_DB"] = path
    try:
        with db.connect() as connection:
            connection.execute("CREATE TABLE control_library (control_id TEXT PRIMARY KEY, name TEXT NOT NULL, framework_refs TEXT NOT NULL, evidence_event_types TEXT NOT NULL, required_fields TEXT NOT NULL, rationale TEXT NOT NULL)")
            connection.execute("INSERT INTO control_library VALUES ('C1', 'legacy', '[]', '[]', '[]', 'r')")
            connection.execute("CREATE TABLE risk_rules (rule_id TEXT PRIMARY KEY, name TEXT NOT NULL, signal TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL, framework_refs TEXT NOT NULL, rationale TEXT NOT NULL)")
            connection.execute("CREATE TABLE review_queue_policies (policy_id TEXT PRIMARY KEY, task_type TEXT NOT NULL, assigned_role TEXT NOT NULL, due_days INTEGER NOT NULL, escalation_days INTEGER NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            connection.execute("CREATE TABLE owner_assignment_policies (policy_id TEXT PRIMARY KEY, subject_type TEXT NOT NULL, owner_role TEXT NOT NULL, applies_to_status TEXT, source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")

        from app.storage.migrations import _0009_config_table_tenancy

        with db.connect() as connection:
            _0009_config_table_tenancy(connection)
            row = connection.execute("SELECT tenant_id FROM control_library WHERE control_id = 'C1'").fetchone()
            assert row["tenant_id"] == ""  # legacy row is now a platform default
            # composite key allows a same-id override under a tenant
            connection.execute("INSERT INTO control_library (tenant_id, control_id, name, framework_refs, evidence_event_types, required_fields, rationale) VALUES ('acme', 'C1', 'override', '[]', '[]', '[]', 'r')")
            assert connection.execute("SELECT COUNT(*) AS c FROM control_library WHERE control_id = 'C1'").fetchone()["c"] == 2
    finally:
        os.unlink(path)
        os.environ.pop("NORINTH_PLATFORM_DB", None)
