"""vendor evidence references that expire

a vendor's agreements and certificates are recorded as typed references with
dates and an optional document hash, never as document content. the
maintenance worker ages them: an expired reference drops an approved vendor
to recertify_due, reopens the unreviewed-vendor finding on every system using
its providers, and blocks the vendor's approval until a current reference
replaces it. a reference near its expiry is announced once
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.helpers import login_and_activate
from tests.test_vendor_registry import RATIONALE, _model_call, _reviewer, _vnd_findings

SHA = "a" * 64


def _days(offset: int) -> str:
    return (datetime.now(UTC).date() + timedelta(days=offset)).isoformat()


@pytest.fixture
def org(super_admin_client):
    from app.main import app

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "acme",
            "name": "Acme",
            "admin_email": "oa@acme.test",
            "admin_display_name": "OA",
            "admin_password": "oa-password-1",
        },
    )
    client = TestClient(app)
    login_and_activate(client, "oa@acme.test", "oa-password-1")
    token = client.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    try:
        yield client, {"Authorization": f"Bearer {token}"}
    finally:
        client.close()


def _vendor(client, name: str = "OpenAI", providers=("openai",)) -> dict:
    created = client.post("/api/vendors", json={"name": name, "providers": list(providers)})
    assert created.status_code == 200, created.text
    return created.json()["vendor"]


def _approve(client, vendor_id: str) -> None:
    assert client.post(f"/api/vendors/{vendor_id}/submit-review").status_code == 200
    stages = [v for v in client.get("/api/vendors").json()["vendors"] if v["vendor_id"] == vendor_id][0]["stages"]
    with _reviewer(client) as reviewer:
        decided = reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide", json={"decision": "approve", "rationale": RATIONALE}
        )
        assert decided.status_code == 200, decided.text


def _record(client, vendor_id: str, **overrides) -> dict:
    body = {
        "kind": "baa",
        "name": "BAA 2026",
        "identifier": "BAA-77",
        "issued_at": _days(-30),
        "expires_at": _days(300),
        "document_hash": SHA,
    }
    body.update(overrides)
    return client.post(f"/api/vendors/{vendor_id}/evidence", json=body)


def _vendor_view(client, vendor_id: str) -> dict:
    return [v for v in client.get("/api/vendors").json()["vendors"] if v["vendor_id"] == vendor_id][0]


def _outbox(event_type: str) -> int:
    from app.storage.raw_events import connect

    with connect() as connection:
        return int(
            connection.execute(
                "SELECT COUNT(*) AS n FROM notification_outbox WHERE event_type = ?", (event_type,)
            ).fetchone()["n"]
        )


def _set_expiry(reference_id: str, value: str) -> None:
    from app.storage.raw_events import connect

    with connect() as connection:
        connection.execute(
            "UPDATE vendor_evidence_references SET expires_at = ? WHERE reference_id = ?", (value, reference_id)
        )


def test_a_reference_is_recorded_as_dates_and_a_hash_never_content(org):
    import json

    client, _ = org
    vendor = _vendor(client)
    recorded = _record(client, vendor["vendor_id"])
    assert recorded.status_code == 200, recorded.text
    reference = recorded.json()["reference"]
    assert reference["status"] == "current"
    assert reference["kind_label"] == "Business associate agreement"
    assert set(reference) >= {"kind", "name", "identifier", "issued_at", "expires_at", "document_hash"}
    assert "content" not in reference and "body" not in reference

    view = _vendor_view(client, vendor["vendor_id"])
    assert [item["reference_id"] for item in view["evidence"]] == [reference["reference_id"]]
    assert view["evidence_expired"] is False
    assert "baa" in client.get("/api/vendors").json()["evidence_kinds"]

    (entry,) = client.get("/api/audit-logs?action=vendor.evidence.record").json()["audit_logs"]
    assert json.loads(entry["detail"])["document_hash"] == SHA


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"kind": "questionnaire"}, "kind must be one of"),
        ({"expires_at": _days(-1)}, "in the future"),
        ({"issued_at": _days(10), "expires_at": _days(5)}, "after issued_at"),
        ({"issued_at": "2026-13-45"}, "must be a date"),
        ({"document_hash": "Z" * 64}, "SHA-256"),
    ],
)
def test_a_bad_reference_is_refused(org, overrides, message):
    client, _ = org
    vendor = _vendor(client)
    refused = _record(client, vendor["vendor_id"], **overrides)
    assert refused.status_code == 400, refused.text
    assert message in refused.json()["detail"]


def test_a_renewed_reference_supersedes_the_earlier_one_of_its_kind(org):
    client, _ = org
    vendor = _vendor(client)
    first = _record(client, vendor["vendor_id"], name="BAA 2025", expires_at=_days(10)).json()["reference"]
    second = _record(client, vendor["vendor_id"], name="BAA 2026", issued_at=_days(-1), expires_at=_days(400)).json()[
        "reference"
    ]
    assert _record(client, vendor["vendor_id"], kind="soc2_type2", name="SOC 2 2026").status_code == 200
    by_id = {item["reference_id"]: item for item in _vendor_view(client, vendor["vendor_id"])["evidence"]}
    assert by_id[first["reference_id"]]["status"] == "superseded"
    assert by_id[second["reference_id"]]["status"] == "current"
    assert sum(1 for item in by_id.values() if item["status"] == "current") == 2


def test_an_expired_reference_lapses_the_vendor_and_reopens_findings(org):
    client, headers = org
    vendor = _vendor(client)
    reference = _record(client, vendor["vendor_id"]).json()["reference"]
    _approve(client, vendor["vendor_id"])
    assert _vendor_view(client, vendor["vendor_id"])["status"] == "approved"
    # a system starts using the covered provider: no finding, the vendor is approved
    assert client.post("/v1/events/batch", json={"events": [_model_call("s1")]}, headers=headers).status_code == 200
    assert _vnd_findings(client) == []

    from app.services.maintenance import run_once

    _set_expiry(reference["reference_id"], _days(-1))
    result = run_once()
    assert result["vendor_evidence_expired"] == 1
    assert result["vendor_recertifications_due"] == 1

    view = _vendor_view(client, vendor["vendor_id"])
    assert view["status"] == "recertify_due"
    assert view["evidence_expired"] is True
    assert [item["status"] for item in view["evidence"]] == ["expired"]
    # the provider is uncovered again and the finding is open on the system using it
    assert client.get("/api/vendors").json()["coverage"]["summary"]["covered"] == 0
    assert any(f["status"] == "open" for f in _vnd_findings(client))
    # one notification per recipient, sent once
    announced = _outbox("vendor.evidence_expired")
    assert announced >= 1
    actions = [e["action"] for e in client.get("/api/audit-logs").json()["audit_logs"]]
    assert "vendor.evidence_expired" in actions and "vendor.recertify_due" in actions
    # idempotent
    again = run_once()
    assert again["vendor_evidence_expired"] == 0 and again["vendor_recertifications_due"] == 0
    assert _outbox("vendor.evidence_expired") == announced


def test_an_expired_reference_blocks_re_review_until_replaced(org):
    client, _ = org
    vendor = _vendor(client)
    reference = _record(client, vendor["vendor_id"]).json()["reference"]
    _approve(client, vendor["vendor_id"])
    _set_expiry(reference["reference_id"], _days(-1))
    from app.services.maintenance import run_once

    run_once()
    refused = client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review")
    assert refused.status_code == 400, refused.text
    assert "expired evidence" in refused.json()["detail"]

    renewed = _record(client, vendor["vendor_id"], name="BAA 2027", issued_at=_days(-1), expires_at=_days(365))
    assert renewed.status_code == 200, renewed.text
    assert _vendor_view(client, vendor["vendor_id"])["evidence_expired"] is False
    _approve(client, vendor["vendor_id"])
    assert _vendor_view(client, vendor["vendor_id"])["status"] == "approved"


def test_a_reference_that_lapses_during_a_review_blocks_the_approval(org):
    client, _ = org
    vendor = _vendor(client)
    reference = _record(client, vendor["vendor_id"]).json()["reference"]
    assert client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review").status_code == 200
    _set_expiry(reference["reference_id"], _days(-1))
    from app.services.maintenance import run_once

    run_once()
    stages = _vendor_view(client, vendor["vendor_id"])["stages"]
    with _reviewer(client) as reviewer:
        decided = reviewer.post(
            f"/api/approval-stages/{stages[0]['stage_id']}/decide", json={"decision": "approve", "rationale": RATIONALE}
        )
        assert decided.status_code == 400, decided.text
        assert "expired evidence" in decided.json()["detail"]
    # the refused decision changed nothing: the stage is still open
    assert _vendor_view(client, vendor["vendor_id"])["stages"][0]["status"] == "open"


def test_withdrawing_an_expired_reference_unblocks_the_vendor(org):
    client, _ = org
    vendor = _vendor(client)
    reference = _record(client, vendor["vendor_id"]).json()["reference"]
    _set_expiry(reference["reference_id"], _days(-1))
    from app.services.maintenance import run_once

    run_once()
    withdrawn = client.post(f"/api/vendors/{vendor['vendor_id']}/evidence/{reference['reference_id']}/withdraw")
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["reference"]["status"] == "withdrawn"
    assert _vendor_view(client, vendor["vendor_id"])["evidence_expired"] is False
    assert client.post(f"/api/vendors/{vendor['vendor_id']}/submit-review").status_code == 200
    (entry,) = client.get("/api/audit-logs?action=vendor.evidence.withdraw").json()["audit_logs"]
    assert entry["target_id"] == reference["reference_id"]


def test_a_reference_near_expiry_is_announced_once(org):
    client, _ = org
    vendor = _vendor(client)
    _record(client, vendor["vendor_id"], issued_at=_days(-300), expires_at=_days(10))
    from app.services.maintenance import run_once

    assert run_once()["vendor_evidence_expiring"] == 1
    assert run_once()["vendor_evidence_expiring"] == 0
    assert _outbox("vendor.evidence_expiring") == 1


def test_evidence_is_tenant_bound_and_needs_config_write(org, super_admin_client):
    from app.main import app

    client, _ = org
    vendor = _vendor(client)
    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": "beta",
            "name": "Beta",
            "admin_email": "oa@beta.test",
            "admin_display_name": "OB",
            "admin_password": "ob-password-1",
        },
    )
    with TestClient(app) as beta:
        login_and_activate(beta, "oa@beta.test", "ob-password-1")
        assert _record(beta, vendor["vendor_id"]).status_code == 404
    with _reviewer(client) as reviewer:
        assert _record(reviewer, vendor["vendor_id"]).status_code == 403


def test_the_audit_packet_carries_references_but_no_documents(org):
    client, _ = org
    vendor = _vendor(client)
    _record(client, vendor["vendor_id"])
    packet = client.get("/api/compliance/audit-packet").json()
    (reference,) = packet["vendor_evidence"]
    assert reference["vendor_id"] == vendor["vendor_id"]
    assert reference["document_hash"] == SHA
    assert not any(key in reference for key in ("content", "body", "text", "document"))
