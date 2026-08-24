"""tenant-isolation fail-closed: actor scope, role scope, sdk-health filtering"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def test_require_actor_scope_fails_closed_on_tenant():
    from app.dependencies import ActorContext
    from app.services.authorization import AuthorizationError, require_actor_scope

    actor = ActorContext(user_ref="u", tenant_id="acme")

    # same tenant: allowed
    require_actor_scope(actor, {"tenant_id": "acme"})

    # different tenant: denied
    try:
        require_actor_scope(actor, {"tenant_id": "beta"})
        raise AssertionError("expected cross-tenant target to be denied")
    except AuthorizationError:
        pass

    # missing/null tenant on the target: denied (fail closed)
    try:
        require_actor_scope(actor, {})
        raise AssertionError("expected NULL-tenant target to be denied")
    except AuthorizationError:
        pass


def test_role_scope_matches_requires_exact_tenant():
    from app.services.authorization import role_scope_matches

    assert role_scope_matches({"tenant_id": "acme"}, {"tenant_id": "acme"}) is True
    assert role_scope_matches({"tenant_id": "acme"}, {"tenant_id": "beta"}) is False
    # a null-scoped assignment is not a wildcard across tenants
    assert role_scope_matches({"tenant_id": None}, {"tenant_id": "acme"}) is False


def _sdk_health(service: str) -> dict:
    return {
        "type": "sdk.health",
        "schema_version": "2026-01",
        "trace_id": f"trc_{service}",
        "span_id": f"spn_{service}",
        "timestamp": "2026-08-22T00:00:00Z",
        "service": service,
        "environment": "prod",
        "project": "p1",
        "attributes": {"mode": "observe", "fail_open": True, "failed_sends": 0, "metadata": {}},
    }


def test_sdk_health_is_tenant_scoped(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    # two orgs; login_and_activate rotates the password, so reuse the live
    # client per tenant rather than re-login
    clients = {}
    tokens = {}
    for tid, email in [("acme", "a@acme.test"), ("beta", "a@beta.test")]:
        super_admin_client.post(
            "/api/admin/organizations",
            json={
                "tenant_id": tid,
                "name": tid,
                "admin_email": email,
                "admin_display_name": f"{tid} admin",
                "admin_password": f"{tid}-admin-pw-1",
            },
        )
        org = TestClient(app)
        login_and_activate(org, email, f"{tid}-admin-pw-1")
        clients[tid] = org
        tokens[tid] = org.post("/api/ingestion-keys", json={"name": f"{tid} key"}).json()["token"]

    try:
        # each tenant ingests an sdk.health event with a distinguishing service
        for tid in ("acme", "beta"):
            resp = clients[tid].post(
                "/v1/events/batch",
                json={"events": [_sdk_health(f"{tid}-service")]},
                headers={"Authorization": f"Bearer {tokens[tid]}"},
            )
            assert resp.status_code == 200, resp.text

        # acme admin sees only acme's sdk.health, never beta's
        health = clients["acme"].get("/api/sdk-health")
        assert health.status_code == 200, health.text
        services = {e.get("service") for e in health.json()["sdk_health"]}
        assert "acme-service" in services
        assert "beta-service" not in services
    finally:
        for org in clients.values():
            org.close()
