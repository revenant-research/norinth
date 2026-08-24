"""tenant erasure clears every tenant-scoped table and suspension freezes users and ingestion"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402

BASE = {"schema_version": "2026-01", "service": "svc", "environment": "prod", "project": "p1"}


def _org(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post("/api/admin/organizations", json={"tenant_id": tenant, "name": tenant, "admin_email": f"a@{tenant}.test", "admin_display_name": "A", "admin_password": f"{tenant}-admin-pw-1"})
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    return org


def test_suspension_freezes_users_and_ingestion(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client, "acme")
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    ping = {**BASE, "type": "sdk.health", "trace_id": "t1", "span_id": "s1", "timestamp": "2026-08-22T00:00:00Z", "attributes": {"mode": "observe", "fail_open": True, "failed_sends": 0, "metadata": {"tenant_id": "acme", "application_name": "A", "workflow_name": "w"}}}
    assert org.post("/v1/events/batch", json={"events": [ping]}, headers=h).status_code == 200
    assert org.get("/api/auth/me").status_code == 200

    super_admin_client.post("/api/admin/organizations/acme/status", json={"status": "suspended"})

    # users and ingestion frozen
    with TestClient(app) as frozen:
        login = frozen.post("/api/auth/login", json={"email": "a@acme.test", "password": "acme-admin-pw-1"})
        # either login refuses or the session is inert
        me = frozen.get("/api/auth/me")
        assert login.status_code != 200 or me.status_code == 403
    assert org.post("/v1/events/batch", json={"events": [ping]}, headers=h).status_code == 403
    org.close()


def test_purge_is_complete_and_kills_scim_token(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    org = _org(super_admin_client, "acme")
    scim = org.post("/api/org/scim-tokens", json={"name": "idp"}).json()["token"]
    org.post("/api/attestation-keys", json={"name": "ci", "public_key_pem": _ed25519_pub()})
    org.post("/api/org/webhooks", json={"name": "wh", "url": "https://example.test/h", "events": ["test"]})
    org.post("/api/ingestion-keys", json={"name": "k"})
    org.close()

    # scim works before purge
    with TestClient(app) as idp:
        r = idp.post("/scim/v2/Users", headers={"Authorization": f"Bearer {scim}", "Content-Type": "application/scim+json"}, json={"userName": "before@acme.test", "active": True})
        assert r.status_code in (201, 409)

    super_admin_client.post("/api/admin/organizations/acme/purge", json={"confirm_tenant_id": "acme"})

    # every tenant-scoped table is empty for acme
    from app.storage.raw_events import connect
    from app.storage.retention import _TENANT_SCOPED_TABLES

    with connect() as connection:
        for table in _TENANT_SCOPED_TABLES:
            n = connection.execute(f"SELECT COUNT(*) AS c FROM {table} WHERE tenant_id = ?", ("acme",)).fetchone()["c"]
            assert n == 0, f"{table} still has acme rows after purge"

    # old scim token cannot resurrect the org
    with TestClient(app) as idp:
        r = idp.post("/scim/v2/Users", headers={"Authorization": f"Bearer {scim}", "Content-Type": "application/scim+json"}, json={"userName": "ghost@acme.test", "active": True})
        assert r.status_code in (401, 403), r.text


def _ed25519_pub() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
