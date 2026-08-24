"""scim 2.0 provisioning lifecycle"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org_with_scim(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, "oa@acme.test", "oa-password-1")
    created = org.post("/api/org/scim-tokens", json={"name": "okta"})
    assert created.status_code == 200, created.text
    token = created.json()["token"]
    assert token.startswith("nrs_")
    assert "token_hash" not in created.json()["scim_token"]
    return org, token


def _scim(token):
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"})
    return client


def test_scim_requires_token(client):
    assert client.get("/scim/v2/Users").status_code == 401
    assert client.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_service_provider_config(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    with _scim(token) as scim:
        resp = scim.get("/scim/v2/ServiceProviderConfig")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/scim+json")
        assert resp.json()["patch"]["supported"] is True
    org.close()


def test_provisioning_lifecycle(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    with _scim(token) as scim:
        # reconcile: idp checks whether the user exists (userName eq filter)
        listing = scim.get('/scim/v2/Users?filter=userName eq "jane@acme.test"')
        assert listing.status_code == 200
        assert listing.json()["totalResults"] == 0

        # create
        created = scim.post(
            "/scim/v2/Users",
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "Jane@Acme.test",
                "externalId": "okta-00u123",
                "name": {"givenName": "Jane", "familyName": "Doe"},
                "emails": [{"value": "jane@acme.test", "primary": True}],
                "active": True,
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["id"] == "jane@acme.test"  # normalized lower-case
        assert body["userName"] == "jane@acme.test"
        assert body["displayName"] == "Jane Doe"
        assert body["externalId"] == "okta-00u123"
        assert body["active"] is True

        # duplicate create is a 409 uniqueness conflict
        dup = scim.post("/scim/v2/Users", json={"userName": "jane@acme.test"})
        assert dup.status_code == 409
        assert dup.json()["scimType"] == "uniqueness"

        # reconcile again finds her
        listing = scim.get('/scim/v2/Users?filter=userName eq "jane@acme.test"')
        assert listing.json()["totalResults"] == 1

        # get by id
        assert scim.get("/scim/v2/Users/jane@acme.test").status_code == 200

        # patch deactivate (entra-style: path-less value object)
        patched = scim.patch(
            "/scim/v2/Users/jane@acme.test",
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "value": {"active": False}}],
            },
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["active"] is False

        # patch reactivate (okta-style: explicit path)
        patched = scim.patch(
            "/scim/v2/Users/jane@acme.test",
            json={"Operations": [{"op": "replace", "path": "active", "value": True}]},
        )
        assert patched.json()["active"] is True

        # put replace display name
        replaced = scim.put(
            "/scim/v2/Users/jane@acme.test",
            json={"userName": "jane@acme.test", "displayName": "Jane D.", "active": True},
        )
        assert replaced.status_code == 200
        assert replaced.json()["displayName"] == "Jane D."

        # delete deprovisions (deactivates, keeps the record for the audit trail)
        assert scim.delete("/scim/v2/Users/jane@acme.test").status_code == 204
        assert scim.get("/scim/v2/Users/jane@acme.test").json()["active"] is False

    # provisioned user got the tenant's default (non-admin) role and is tenant-bound
    users = org.get("/api/org/users").json()["users"]
    jane = next(u for u in users if u["user_ref"] == "jane@acme.test")
    assert jane["tenant_id"] == "acme"
    # least-privilege default: read-only viewer, never a decision or admin role
    # merely for existing in the idp directory
    assert "governance_viewer" in jane["roles"]
    assert "governance_reviewer" not in jane["roles"]
    assert "org_admin" not in jane["roles"]
    org.close()


def test_deactivation_revokes_live_sessions(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    # create a normal password user, log them in, then deprovision via scim
    org.post("/api/org/users", json={"email": "bob@acme.test", "display_name": "Bob", "password": "bob-password-1"})
    from app.main import app
    from fastapi.testclient import TestClient

    bob = TestClient(app)
    login_and_activate(bob, "bob@acme.test", "bob-password-1")
    assert bob.get("/api/auth/me").status_code == 200

    with _scim(token) as scim:
        assert scim.patch(
            "/scim/v2/Users/bob@acme.test",
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        ).status_code == 200

    # bob's existing session is dead immediately
    assert bob.get("/api/auth/me").status_code in (401, 403)
    bob.close()
    org.close()


def test_scim_is_tenant_isolated(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    # a second org's admin user must be invisible and untouchable via acme's token
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "beta",
            "name": "beta",
            "admin_email": "a@beta.test",
            "admin_display_name": "B",
            "admin_password": "beta-password-1",
        },
    )
    with _scim(token) as scim:
        assert scim.get("/scim/v2/Users/a@beta.test").status_code == 404
        assert scim.delete("/scim/v2/Users/a@beta.test").status_code == 404
        # creating a userName that exists in another tenant is a conflict, not a takeover
        assert scim.post("/scim/v2/Users", json={"userName": "a@beta.test"}).status_code == 409
        names = {u["userName"] for u in scim.get("/scim/v2/Users").json()["Resources"]}
        assert "a@beta.test" not in names
    org.close()


def test_revoked_token_is_rejected(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    token_id = org.get("/api/org/scim-tokens").json()["scim_tokens"][0]["token_id"]
    assert org.post(f"/api/org/scim-tokens/{token_id}/revoke").status_code == 200
    with _scim(token) as scim:
        assert scim.get("/scim/v2/Users").status_code == 401
    org.close()


def test_unsupported_filter_is_400(super_admin_client):
    org, token = _org_with_scim(super_admin_client)
    with _scim(token) as scim:
        assert scim.get('/scim/v2/Users?filter=displayName co "x"').status_code == 400
    org.close()
