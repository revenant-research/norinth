"""one spelling of an email address names one account

identity providers, SCIM and the login form lowercase addresses; accounts
created by an administrator kept the spelling the administrator typed. a
mixed-case invite and a SCIM-provisioned lowercase account became two users,
and a SCIM deactivation of the leaver missed the first
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import login_and_activate


def _org(super_admin_client):
    from app.main import app

    created = super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "OA@Acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["org_admin"]["user_ref"] == "oa@acme.test"
    org = TestClient(app)
    org.__enter__()
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    return org


def test_an_admin_created_account_is_stored_and_found_lowercase(super_admin_client):
    from app.main import app
    from app.storage.workflow import get_user_by_email

    org = _org(super_admin_client)
    created = org.post(
        "/api/org/users", json={"email": "  Alice@Acme.test ", "display_name": "Alice", "password": "alice-pw-123456"}
    )
    assert created.status_code == 200, created.text
    assert created.json()["user"]["user_ref"] == "alice@acme.test"
    assert created.json()["user"]["email"] == "alice@acme.test"
    assert created.json()["invite_url"].endswith(created.json()["invite_url"].rsplit("/", 1)[1])

    # the same address in any spelling is the same account
    assert (
        org.post(
            "/api/org/users", json={"email": "ALICE@ACME.TEST", "display_name": "Dup", "password": "dup-pw-1234567"}
        ).status_code
        == 409
    )
    assert get_user_by_email("Alice@ACME.test")["user_ref"] == "alice@acme.test"

    with TestClient(app) as alice:
        login = alice.post("/api/auth/login", json={"email": "ALICE@acme.test", "password": "alice-pw-123456"})
        assert login.status_code == 200, login.text
    org.close()


def test_an_account_created_before_normalisation_is_still_found(super_admin_client):
    from app.storage.raw_events import connect
    from app.storage.workflow import get_user_by_email

    org = _org(super_admin_client)
    with connect() as connection:
        connection.execute(
            "INSERT INTO platform_users (user_ref, display_name, email, status, tenant_id, created_at, updated_at) "
            "VALUES ('Legacy@Acme.test', 'Legacy', 'Legacy@Acme.test', 'active', 'acme', datetime('now'), datetime('now'))"
        )
    found = get_user_by_email("legacy@acme.test")
    assert found is not None and found["user_ref"] == "Legacy@Acme.test"
    # and cannot be duplicated under the lowercase spelling
    assert (
        org.post(
            "/api/org/users", json={"email": "legacy@acme.test", "display_name": "Dup", "password": "dup-pw-1234567"}
        ).status_code
        == 409
    )
    org.close()
