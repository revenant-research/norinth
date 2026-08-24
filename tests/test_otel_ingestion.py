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
