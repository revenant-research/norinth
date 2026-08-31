# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""only deliberately written messages reach the caller

a single handler answered every ValueError with str(exc), so an incidental one
returned its own wording: int() on a bad token count answered with "invalid
literal for int() with base 10", and an internal invariant in the sql layer
answered with a table name. DomainError now carries the messages meant for
callers; everything else is logged and answered generically
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage import retention  # noqa: E402
from app.storage.errors import DomainError  # noqa: E402

from tests.helpers import login_and_activate  # noqa: E402


def _org(super_admin_client):
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
    return org


def test_domain_error_message_reaches_the_caller(super_admin_client):
    org = _org(super_admin_client)
    resp = org.post("/api/retention-policy", json={"retention_days": 3})
    assert resp.status_code == 400, resp.text
    # written for whoever sent the request, so it is returned verbatim
    assert resp.json()["detail"] == (
        "retention_days must be at least 7, or null to keep everything"
    )
    org.close()


def test_incidental_value_error_message_is_not_returned(super_admin_client, monkeypatch, caplog):
    org = _org(super_admin_client)

    def _raise_internal(*args, **kwargs):
        raise ValueError("invalid literal for int() with base 10: 'nope' in table sdk_events")

    monkeypatch.setattr(retention, "set_retention_days", _raise_internal)
    import app.api.routes as routes

    monkeypatch.setattr(routes, "set_retention_days", _raise_internal, raising=False)

    with caplog.at_level("WARNING"):
        resp = org.post("/api/retention-policy", json={"retention_days": 30})

    assert resp.status_code == 400, resp.text
    assert resp.json() == {"detail": "Invalid request"}
    body = resp.text
    for leaked in ("invalid literal", "int()", "sdk_events"):
        assert leaked not in body, f"{leaked!r} reached the caller"
    # the operator still gets the real message
    assert any("invalid literal" in record.getMessage() for record in caplog.records)
    org.close()


def test_domain_error_is_a_value_error():
    """existing except-ValueError call sites keep catching these"""
    assert issubclass(DomainError, ValueError)
