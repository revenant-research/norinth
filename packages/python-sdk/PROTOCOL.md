# Norinth Wire Protocol

**Version:** `2026-01` (`SCHEMA_VERSION`)

This document specifies the contract between the open Norinth SDK (the client)
and any receiver (the Norinth Platform, or a self-hosted collector). It is the
single seam between the open and commercial components. Any client that emits
this format is Norinth-compatible; any server that accepts it can ingest
Norinth telemetry.

## Transport

- **Method:** `POST`
- **Path:** `/v1/events/batch`
- **Endpoint:** caller-configured (`NORINTH_ENDPOINT`). The SDK appends the path
  to the configured base URL.

### Headers

| Header | Required | Description |
|---|---|---|
| `Content-Type` | yes | `application/json` |
| `Authorization` | yes | `Bearer <api_key>` |
| `X-Norinth-Signature` | optional | `sha256=<hex>` HMAC of the raw body (see Signing) |

### Request body

```json
{
  "events": [ { /* NorinthEvent */ } ]
}
```

### Response

```json
{ "accepted": 12, "total": 4096 }
```

`accepted` is the number of events ingested from this batch; `total` is the
receiver's cumulative event count. Receivers SHOULD return `401` on signature
failure and `4xx` on malformed batches. Clients are fail-open and MUST NOT
propagate transport errors into host application code.

## The `NorinthEvent` object

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | string | yes | Event type (see below) |
| `schema_version` | string | yes | `"2026-01"` |
| `trace_id` | string | yes | Correlates events within one request |
| `span_id` | string | yes | Unique per event |
| `parent_span_id` | string \| null | no | Links a child span to its parent |
| `timestamp` | string | yes | ISO-8601 UTC |
| `service` | string | yes | Emitting service name |
| `environment` | string | yes | e.g. `production`, `staging` |
| `project` | string | yes | Logical project grouping |
| `system` | string \| null | no | Subsystem / app identifier |
| `name` | string \| null | no | Operation or entity name |
| `status` | string | yes | `success` \| `error` (defaults `success`) |
| `duration_ms` | number \| null | no | Wall-clock duration |
| `attributes` | object | yes | Type-specific payload (see below) |

### `attributes.metadata` convention

Governance context travels in `attributes.metadata`. Recognized keys:

- `tenant_id` — owning tenant (drives multi-tenant scoping)
- `user_id` — acting user
- `application_name` — business application
- `workflow_name` — business process
- `use_case`, `model_purpose` — free-text governance context

## Event types

| `type` | Emitted by | Key `attributes` |
|---|---|---|
| `sdk.health` | SDK lifecycle | `mode`, `fail_open`, `async_transport`, `durable`, `spool_configured`, `endpoint`, transport counters |
| `trace.completed` | request/trace wrapper | `metadata`, `error` |
| `model.call` | provider auto-instrumentation | `provider`, `model`, `operation`, `prompt`, `response`, `usage`, `error` |
| `retrieval.call` | `retrieval()` | `retriever`, `query`, `documents`, `document_count` |
| `tool.call` | `tool_call()` | `tool_name`, `arguments`, `result` |
| `guardrail.decision` | `guardrail()` | `guardrail_name`, `decision`, `score`, `matched_rules` |
| `eval.result` | `eval_result()` | `eval_name`, `score`, `threshold`, `passed` |
| `agent.run` | `agent_run()` | `agent_name`, `steps`, `step_count`, `outcome` |
| `prompt.event` | `prompt()` | `prompt_id`, `version`, `artifact_ref`, `prompt_status`, `template` |
| `deployment.event` | `deployment()` | `deployment_id`, `version`, `artifact_ref`, `deployment_status`, `provider`, `model` |
| `incident.event` | `incident()` | `incident_id`, `title`, `severity`, `incident_status`, `description` |

## Content privacy

By default, free-text fields such as `prompt`, `response`, `query`,
`arguments`, `result`, `template`, and `description` are **summarized and
hashed**, not transmitted in plaintext. Raw content is transmitted only when
content capture is explicitly enabled on the client. Receivers MUST treat the
presence of raw content as opt-in and never assume it.

## Signing (optional payload attestation)

When a signing secret is configured, the client computes:

```
signature = HMAC_SHA256(key = signing_secret, message = <raw JSON body bytes>)
header    = "sha256=" + hex(signature)
```

The body bytes are the exact serialized request payload
(`{"events": [...]}` with compact separators). The receiver recomputes the
HMAC over the raw body it received and compares using a constant-time check.
A mismatch or missing signature, when verification is required, MUST be
rejected with `401`.

This lets a receiver verify that a batch was produced by a holder of the
shared secret and was not altered in transit — the basis for treating Norinth
telemetry as attested evidence rather than an editable document.
