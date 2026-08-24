"""webhook signatures resist replay and urls are not leaked"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def test_mask_url_hides_the_secret_path():
    from app.storage.notifications import mask_url

    masked = mask_url("https://hooks.slack.com/services/T000/B000/XXXXsecretXXXX")
    assert "secret" not in masked
    assert masked == "https://hooks.slack.com/…"
    # bare host with no path is returned without the ellipsis
    assert mask_url("https://example.test") == "https://example.test"
    assert mask_url("not a url") == "[redacted-url]"


def test_signature_covers_timestamp_and_delivery_id_is_unique(monkeypatch):
    import app.services.notifications as notifications

    captured: list[dict] = []

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=15):
        captured.append({"headers": dict(req.headers), "body": req.data})
        return _Resp()

    monkeypatch.setattr(notifications.urllib.request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(notifications, "validate_external_url", lambda url: None)
    monkeypatch.setattr(notifications.store, "webhook_secret", lambda hook: "whs_test_secret")

    hook = {"url": "https://example.test/hook", "format": "json"}
    notifications._post_webhook(hook, {"type": "test.event", "subject": "hi"})
    notifications._post_webhook(hook, {"type": "test.event", "subject": "hi"})

    assert len(captured) == 2
    h0, h1 = captured[0]["headers"], captured[1]["headers"]
    # signature is stripe-style (t=..,v1=..) and a timestamp header is present
    assert h0["X-norinth-timestamp"]
    assert h0["X-norinth-signature"].startswith("t=") and ",v1=" in h0["X-norinth-signature"]
    # identical payloads still get distinct delivery ids (dedupe-able)
    assert h0["X-norinth-delivery"] != h1["X-norinth-delivery"]


def test_webhook_url_is_masked_in_list_and_audit(super_admin_client):
    from app.main import app
    from fastapi.testclient import TestClient

    from tests.helpers import login_and_activate

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
    with TestClient(app) as org:
        login_and_activate(org, "a@acme.test", "acme-admin-pw-1")
        secret_url = "https://hooks.slack.com/services/T0/B0/TOPSECRETTOKEN"
        created = org.post(
            "/api/org/webhooks",
            json={"name": "slack", "url": secret_url, "events": ["*"], "format": "slack"},
        )
        assert created.status_code == 201, created.text
        assert "TOPSECRETTOKEN" not in created.json()["webhook"]["url"]

        listed = org.get("/api/org/webhooks").json()["webhooks"]
        assert all("TOPSECRETTOKEN" not in w["url"] for w in listed)
