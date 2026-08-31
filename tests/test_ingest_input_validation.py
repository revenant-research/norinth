# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""malformed ingest payloads are described errors, never 500s

the validator checked that usage was an object and stopped there, so int() met
whatever was inside it: a list raised TypeError, 1e400 raised OverflowError, and
a non-numeric string raised ValueError that the global handler returned verbatim
to the caller. the otlp envelope was walked with no structural check at all, so
a string where an array belonged was iterated as characters
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from app.storage.raw_events import as_int  # noqa: E402

from tests.helpers import login_and_activate  # noqa: E402

BASE = {
    "type": "model.call",
    "schema_version": "2026-01",
    "timestamp": "2026-08-22T00:00:00Z",
    "service": "svc",
    "environment": "prod",
    "project": "p1",
}


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
    token = org.post("/api/ingestion-keys", json={"name": "k"}).json()["token"]
    return org, token


def _post(org, token, usage):
    event = {**BASE, "trace_id": "t1", "span_id": "s1", "attributes": {"usage": usage, "metadata": {}}}
    return org.post("/v1/events/batch", json={"events": [event]}, headers={"Authorization": f"Bearer {token}"})


def _otel(org, token, payload):
    return org.post("/v1/otel/traces", json=payload, headers={"Authorization": f"Bearer {token}"})


@pytest.mark.parametrize(
    "value",
    ["not-a-number", [1, 2, 3], {"a": 1}],
    ids=["string", "list", "object"],
)
def test_uncountable_usage_is_422_not_500(super_admin_client, value):
    org, token = _org(super_admin_client)
    resp = _post(org, token, {"input_tokens": value})
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert detail.startswith("events[0].attributes.usage.input_tokens must be")
    # the global ValueError handler used to hand the caller int()'s own message
    assert "invalid literal" not in detail and "int()" not in detail
    org.close()


def test_overflowing_number_literal_is_422(super_admin_client):
    """1e400 is valid json that parses to inf, so it arrives as a raw body

    int(inf) raises OverflowError, which is not a ValueError and so escaped the
    handler entirely
    """
    org, token = _org(super_admin_client)
    body = (
        '{"events":[{"type":"model.call","schema_version":"2026-01","trace_id":"t1","span_id":"s1",'
        '"timestamp":"2026-08-22T00:00:00Z","service":"svc","project":"p1","environment":"prod",'
        '"attributes":{"usage":{"input_tokens":1e400}}}]}'
    )
    resp = org.post(
        "/v1/events/batch",
        content=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"] == "events[0].attributes.usage.input_tokens must be a finite number"
    org.close()


@pytest.mark.parametrize(
    "usage",
    [{"input_tokens": 10, "output_tokens": 5}, {"input_tokens": "12"}, {"input_tokens": 1.5}, {}],
    ids=["ints", "numeric-strings", "float", "absent"],
)
def test_countable_usage_still_accepted(super_admin_client, usage):
    org, token = _org(super_admin_client)
    resp = _post(org, token, usage)
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1
    org.close()


@pytest.mark.parametrize(
    "payload,path",
    [
        ({"resourceSpans": "oops"}, "resourceSpans"),
        ({"resourceSpans": [1, 2, 3]}, "resourceSpans[0]"),
        ({"resourceSpans": [{"resource": "oops"}]}, "resourceSpans[0].resource"),
        ({"resourceSpans": [{"scopeSpans": "oops"}]}, "resourceSpans[0].scopeSpans"),
        ({"resourceSpans": [{"scopeSpans": [{"spans": "oops"}]}]}, "resourceSpans[0].scopeSpans[0].spans"),
        (
            {"resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": "oops"}]}]}]},
            "resourceSpans[0].scopeSpans[0].spans[0].attributes",
        ),
    ],
)
def test_malformed_otlp_envelope_is_400_naming_the_path(super_admin_client, payload, path):
    org, token = _org(super_admin_client)
    resp = _otel(org, token, payload)
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"].startswith(path)
    org.close()


def test_valid_otlp_span_survives_one_odd_attribute(super_admin_client):
    """the envelope is the caller's contract; a single bad attribute is not"""
    org, token = _org(super_admin_client)
    resp = _otel(
        org,
        token,
        {
            "resourceSpans": [
                {
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}]},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "tr1",
                                    "spanId": "sp1",
                                    "name": "chat",
                                    "endTimeUnixNano": "1756598400000000000",
                                    "attributes": [
                                        {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                                        {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "7"}},
                                        {"key": "malformed", "value": "not-an-object"},
                                        "not-even-a-pair",
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1
    org.close()


@pytest.mark.parametrize(
    "value,expected",
    [
        (10, 10), ("12", 12), (1.5, 1), (None, 0), ("", 0), ("nope", 0),
        ([1, 2], 0), ({"a": 1}, 0), (float("inf"), 0), (float("nan"), 0), (True, 0), (-3, -3),
    ],
)
def test_as_int_never_raises(value, expected):
    """storage-side second line: the raw rows are committed before the fold runs"""
    assert as_int(value) == expected
