"""opentelemetry genai ingestion path"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))


def _otlp_chat_span() -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "otel-app"}},
                        {"key": "deployment.environment", "value": {"stringValue": "prod"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "abc123",
                                "spanId": "def456",
                                "name": "chat gpt-4o",
                                "endTimeUnixNano": "1755820800000000000",
                                "attributes": [
                                    {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                                    {"key": "gen_ai.provider.name", "value": {"stringValue": "openai"}},
                                    {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
                                    {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "12"}},
                                    {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "8"}},
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }


def test_otel_mapper_maps_chat_to_model_call():
    from app.ingestion.otel import otel_spans_to_events

    events = otel_spans_to_events(_otlp_chat_span())
    assert len(events) == 1
    event = events[0]
    assert event["type"] == "model.call"
    assert event["attributes"]["provider"] == "openai"
    assert event["attributes"]["model"] == "gpt-4o"
    assert event["attributes"]["usage"]["input_tokens"] == 12
    assert event["attributes"]["metadata"]["application_name"] == "otel-app"


def test_otel_mapper_skips_non_genai_spans():
    from app.ingestion.otel import otel_spans_to_events

    payload = {
        "resourceSpans": [
            {"scopeSpans": [{"spans": [{"name": "GET /health", "attributes": [{"key": "http.method", "value": {"stringValue": "GET"}}]}]}]}
        ]
    }
    assert otel_spans_to_events(payload) == []


def test_otel_endpoint_ingests_and_populates_inventory(client):
    resp = client.post(
        "/v1/otel/traces",
        json=_otlp_chat_span(),
        headers={"Authorization": "Bearer dev"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 1

    # otel-sourced model call shows up as an application under the key's tenant
    from app.storage.entities import connect

    with connect() as connection:
        row = connection.execute(
            "SELECT application_name, providers FROM governance_applications WHERE tenant_id = 'tenant-local'"
        ).fetchone()
    assert row is not None
    assert row["application_name"] == "otel-app"


def test_otel_endpoint_requires_key(client):
    assert client.post("/v1/otel/traces", json=_otlp_chat_span()).status_code == 401


def test_otel_endpoint_handles_no_genai_spans(client):
    resp = client.post(
        "/v1/otel/traces",
        json={"resourceSpans": []},
        headers={"Authorization": "Bearer dev"},
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 0


def test_otel_endpoint_enforces_the_body_signature_when_configured(client, monkeypatch):
    """the OTLP path must not be an unsigned way in when body signing is required"""
    import hashlib
    import hmac
    import json

    monkeypatch.setenv("NORINTH_SIGNING_SECRET", "topsecret")
    body = json.dumps(_otlp_chat_span()).encode("utf-8")
    common = {"Authorization": "Bearer dev", "Content-Type": "application/json"}

    # no signature is rejected
    missing = client.post("/v1/otel/traces", content=body, headers=common)
    assert missing.status_code == 401, missing.text

    # a wrong signature is rejected
    bad = client.post("/v1/otel/traces", content=body, headers={**common, "X-Norinth-Signature": "sha256=deadbeef"})
    assert bad.status_code == 401, bad.text

    # the correct signature over the raw body is accepted
    sig = "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    ok = client.post("/v1/otel/traces", content=body, headers={**common, "X-Norinth-Signature": sig})
    assert ok.status_code == 200, ok.text


def _many_genai_spans(n: int) -> dict:
    spans = [
        {
            "name": "chat gpt-4o",
            "traceId": f"t{i}",
            "spanId": f"s{i}",
            "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.provider.name", "value": {"stringValue": "openai"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
            ],
        }
        for i in range(n)
    ]
    return {"resourceSpans": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "otel-app"}}]},
        "scopeSpans": [{"spans": spans}],
    }]}


def test_otel_endpoint_caps_the_number_of_spans_per_request(client):
    """OTLP builds its own event list, so it must enforce the same per-request
    cap the native batch endpoint gets from its schema"""
    from app.schemas.events import MAX_BATCH_EVENTS

    over = client.post(
        "/v1/otel/traces",
        json=_many_genai_spans(MAX_BATCH_EVENTS + 1),
        headers={"Authorization": "Bearer dev"},
    )
    assert over.status_code == 413, over.text


def test_otel_mapper_skips_attributes_whose_key_is_not_a_string():
    """found by fuzzing: a list as an attribute key raised TypeError on assignment, a 500 to the collector"""
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"].append({"key": ["not", "a", "string"], "value": {"stringValue": "x"}})
    payload["resourceSpans"][0]["resource"]["attributes"].append({"key": {"nested": 1}, "value": {"stringValue": "x"}})

    events = otel_spans_to_events(payload)
    assert len(events) == 1
    assert events[0]["type"] == "model.call"


def test_otel_mapper_treats_structured_operation_name_as_not_genai():
    """found by fuzzing: a dict in stringValue raised TypeError on the operation lookup"""
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"][0] = {"key": "gen_ai.operation.name", "value": {"stringValue": {"not": "a string"}}}

    assert otel_spans_to_events(payload) == []


def test_otel_mapper_falls_back_when_timestamp_is_outside_the_datetime_range():
    from app.ingestion.otel import otel_spans_to_events

    for nanos in (10**40, -(10**30), "1e400", float("inf"), float("nan")):
        payload = _otlp_chat_span()
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["endTimeUnixNano"] = nanos
        (event,) = otel_spans_to_events(payload)
        assert isinstance(event["timestamp"], str), nanos
