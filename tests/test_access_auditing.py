"""failures and reads are on the audit record, not just mutations

"who viewed this record" and "who tried to get in" must have answers: an
audit trail that only sees successful writes cannot support an access review,
and the compensating notification for an operator password reset assumes the
org can see failed logins against its accounts.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _detail(entry: dict) -> dict:
    import json

    raw = entry.get("detail")
    return json.loads(raw) if isinstance(raw, str) else (raw or {})


def _make_org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant,
            "name": tenant,
            "admin_email": f"a@{tenant}.test",
            "admin_display_name": "A",
            "admin_password": f"{tenant}-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    return org


def _audit_actions(client, **filters) -> list[dict]:
    params = "&".join(f"{key}={value}" for key, value in filters.items())
    response = client.get(f"/api/audit-logs?{params}")
    assert response.status_code == 200, response.text
    return response.json()["audit_logs"]


def test_failed_login_is_audited_with_source(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    _make_org(super_admin_client, "acme").close()
    anonymous = TestClient(app)
    anonymous.post("/api/auth/login", json={"email": "a@acme.test", "password": "wrong-password-1"})

    entries = _audit_actions(super_admin_client, action="auth.login_failed")
    assert entries, "failed login left no audit record"
    entry = entries[0]
    assert entry["actor_ref"] == "a@acme.test"
    # the attempt targeted a real acme account, so acme's admins can see it
    assert entry["tenant_id"] == "acme"
    assert _detail(entry)["account_exists"] is True
    assert "source_ip" in _detail(entry)
    anonymous.close()


def test_failed_login_against_unknown_email_is_audited_platform_wide(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    anonymous = TestClient(app)
    anonymous.post("/api/auth/login", json={"email": "ghost@nowhere.test", "password": "whatever-1"})

    entries = _audit_actions(super_admin_client, action="auth.login_failed", actor_ref="ghost@nowhere.test")
    assert entries and entries[0]["tenant_id"] is None
    assert _detail(entries[0])["account_exists"] is False
    anonymous.close()


def test_lockout_is_audited_exactly_once(super_admin_client):
    from app.main import app
    from app.storage.login_attempts import LOCKOUT_THRESHOLD
    from fastapi.testclient import TestClient

    _make_org(super_admin_client, "beta").close()
    anonymous = TestClient(app)
    for _ in range(LOCKOUT_THRESHOLD + 2):  # attempts past the threshold get 429s
        anonymous.post("/api/auth/login", json={"email": "a@beta.test", "password": "bad-password-1"})

    lockouts = [
        e for e in _audit_actions(super_admin_client, action="auth.lockout") if e["actor_ref"] == "a@beta.test"
    ]
    assert len(lockouts) == 1, f"expected exactly one lockout event, got {len(lockouts)}"
    assert "email:a@beta.test" in _detail(lockouts[0])["subjects"]
    anonymous.close()


def test_reading_events_is_an_access_event(super_admin_client):
    org = _make_org(super_admin_client, "gamma")
    assert org.get("/api/events").status_code == 200

    entries = _audit_actions(org, action="access.events")
    assert entries, "events read left no audit record"
    assert entries[0]["actor_ref"] == "a@gamma.test"
    assert entries[0]["tenant_id"] == "gamma"
    assert _detail(entries[0])["returned"] == 0
    org.close()


def test_aibom_export_is_audited(super_admin_client):
    org = _make_org(super_admin_client, "delta")
    assert org.get("/api/compliance/aibom").status_code == 200

    entries = _audit_actions(org, action="compliance.aibom")
    assert entries and entries[0]["tenant_id"] == "delta"
    org.close()


def test_reading_the_audit_trail_is_itself_recorded(super_admin_client):
    org = _make_org(super_admin_client, "epsilon")
    org.get("/api/audit-logs")
    entries = _audit_actions(org, action="access.audit_logs")
    assert entries, "audit-trail read left no audit record"
    assert entries[0]["tenant_id"] == "epsilon"
    org.close()


def test_operator_data_preview_is_visible_to_the_tenant(super_admin_client):
    org = _make_org(super_admin_client, "zeta")
    assert super_admin_client.get("/api/admin/organizations/zeta/data").status_code == 200

    # the tenant's own admin can see the operator looked
    entries = _audit_actions(org, action="access.tenant_data_preview")
    assert entries and entries[0]["tenant_id"] == "zeta"
    org.close()


def test_audit_chain_still_verifies_with_access_events(super_admin_client):
    org = _make_org(super_admin_client, "eta")
    org.get("/api/events")
    org.get("/api/audit-logs")
    verdict = super_admin_client.get("/api/admin/audit-logs/verify").json()
    assert verdict.get("ok") is True, verdict
    org.close()
