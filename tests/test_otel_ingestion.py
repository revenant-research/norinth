"""opentelemetry genai ingestion path"""

from __future__ import annotations

import pathlib
import sys

import pytest

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
            {
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "GET /health",
                                "attributes": [{"key": "http.method", "value": {"stringValue": "GET"}}],
                            }
                        ]
                    }
                ]
            }
        ]
    }
    assert otel_spans_to_events(payload) == []


def test_otel_mapper_records_executed_model_and_preserves_requested_model(client):
    """A routed response must populate inventory with the model that actually ran."""
    import json

    from app.ingestion.otel import otel_spans_to_events
    from app.storage.entities import connect

    payload = _otlp_chat_span()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"].append({"key": "gen_ai.response.model", "value": {"stringValue": "gpt-4o-actual"}})
    (event,) = otel_spans_to_events(payload)
    assert event["attributes"]["model"] == "gpt-4o-actual"
    assert event["attributes"]["requested_model"] == "gpt-4o"
    response = client.post("/v1/otel/traces", json=payload, headers={"Authorization": "Bearer dev"})
    assert response.status_code == 200, response.text
    with connect() as connection:
        row = connection.execute(
            "SELECT models FROM governance_applications WHERE tenant_id = 'tenant-local'"
        ).fetchone()
    assert json.loads(row["models"]) == ["gpt-4o-actual"]


def test_otel_mapper_accepts_a_response_model_without_a_request_model():
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    attributes = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
    attributes[:] = [attr for attr in attributes if attr["key"] != "gen_ai.request.model"]
    attributes.append({"key": "gen_ai.response.model", "value": {"stringValue": "actual-model"}})
    (event,) = otel_spans_to_events(payload)
    assert event["attributes"]["model"] == "actual-model"
    assert event["attributes"].get("requested_model") is None


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
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "otel-app"}}]},
                "scopeSpans": [{"spans": spans}],
            }
        ]
    }


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


def test_otel_mapper_preserves_numeric_attributes_that_overflow_conversion():
    """Fuzzing found intValue infinity escaping as OverflowError instead of falling back."""
    import json

    from app.ingestion.otel import otel_spans_to_events

    for kind, raw in (
        ("intValue", float("inf")),
        ("intValue", float("-inf")),
        ("intValue", float("nan")),
        ("doubleValue", 10**400),
    ):
        payload = _otlp_chat_span()
        span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        span["attributes"].append({"key": "gen_ai.usage.input_tokens", "value": {kind: raw}})
        (event,) = otel_spans_to_events(payload)
        assert event["attributes"]["usage"]["input_tokens"] is raw
        json.dumps(event)


def _span_with(**overrides) -> dict:
    payload = _otlp_chat_span()
    payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0].update(overrides)
    return payload


def test_otel_mapper_skips_attribute_values_that_are_not_scalars():
    """a container where a scalar belongs would fail at the sql binding, after
    the request was accepted; it is skipped like any other malformed attribute"""
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    payload["resourceSpans"][0]["resource"]["attributes"][0] = {"key": "service.name", "value": {"stringValue": {}}}
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"][1] = {"key": "gen_ai.provider.name", "value": {"stringValue": []}}
    span["attributes"][3] = {"key": "gen_ai.usage.input_tokens", "value": {"intValue": [12]}}
    span["attributes"].append({"key": "gen_ai.agent.name", "value": {"boolValue": {"nested": True}}})

    (event,) = otel_spans_to_events(payload)
    assert event["service"] == "otel"
    assert event["attributes"]["provider"] is None
    assert event["attributes"]["usage"]["input_tokens"] is None
    assert event["attributes"]["metadata"]["application_name"] == "otel"


@pytest.mark.parametrize("field", ["name", "parentSpanId", "traceId", "spanId"])
def test_otel_mapper_rejects_a_container_in_a_span_envelope_field(field):
    from app.ingestion.otel import OtelPayloadError, otel_spans_to_events

    for bad in ([], {}, ["a", "b"], {"k": "v"}):
        with pytest.raises(OtelPayloadError, match=field):
            otel_spans_to_events(_span_with(**{field: bad}))


def test_otel_endpoint_answers_400_not_500_for_a_container_in_an_envelope_field(client):
    from app.storage.raw_events import connect

    payload = _span_with(name=["chat", "gpt-4o"], parentSpanId={})
    response = client.post("/v1/otel/traces", json=payload, headers={"Authorization": "Bearer dev"})
    assert response.status_code == 400, response.text
    assert "name" in response.json()["detail"]
    with connect() as connection:
        assert connection.execute("SELECT COUNT(*) AS n FROM sdk_events").fetchone()["n"] == 0


def test_otel_endpoint_ingests_a_span_whose_attribute_values_are_containers(client):
    """the span is still well-formed; only the odd attributes are dropped"""
    payload = _otlp_chat_span()
    payload["resourceSpans"][0]["resource"]["attributes"][0] = {"key": "service.name", "value": {"stringValue": {}}}
    response = client.post("/v1/otel/traces", json=payload, headers={"Authorization": "Bearer dev"})
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1


def test_otel_mapper_renders_numeric_names_as_text():
    """a sender may encode a namespace or data-source id as a number; the
    columns those land in are text, on both databases"""
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    payload["resourceSpans"][0]["resource"]["attributes"].append(
        {"key": "service.namespace", "value": {"intValue": "7813586424118473845"}}
    )
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"][0] = {"key": "gen_ai.operation.name", "value": {"stringValue": "retrieval"}}
    span["attributes"].append({"key": "gen_ai.data_source.id", "value": {"intValue": "42"}})
    span["attributes"].append({"key": "gen_ai.response.model", "value": {"doubleValue": "1.5"}})

    (event,) = otel_spans_to_events(payload)
    assert event["project"] == "7813586424118473845"
    assert event["attributes"]["retriever"] == "42"
    assert event["attributes"]["model"] == "1.5"


def test_otel_mapper_renders_a_non_string_operation_name_as_text():
    """a bool operation name is not a gen_ai operation, but a retrieval span
    still maps, and the name it carries must be text"""
    from app.ingestion.otel import otel_spans_to_events

    payload = _otlp_chat_span()
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"][0] = {"key": "gen_ai.operation.name", "value": {"boolValue": True}}
    span["attributes"].append({"key": "gen_ai.data_source.id", "value": {"stringValue": "kb"}})
    del span["name"]

    (event,) = otel_spans_to_events(payload)
    assert event["type"] == "retrieval.call"
    assert event["name"] == "true" and event["attributes"]["operation"] == "true"
