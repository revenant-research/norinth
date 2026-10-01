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

### Release gate checks

`GET /v1/gates/check` uses the ingestion key's tenant and requires
`deployment_id` and `version`. Supply `project` and `environment` to identify
the intended release scope. A missing gate returns `404`; an ambiguous lookup
returns `409` rather than selecting a gate from another environment or project.

The response's `approved`, `status`, `decided_by`, and `decided_at` describe the
recorded human decision. They remain historical facts when new evidence arrives.
`project`, `environment`, and `artifact_ref` identify the checked release.

The additive `current_eligibility` object reports `eligible`, `blockers`, `reason`,
`policy_tenant`, `policy_version`, and `checked_at`. Eligibility requires an
approved gate and no current blockers. Blocker codes are `release_not_approved`,
`pending_evidence`, `open_risks`, `missing_controls`, `insufficient_coverage`,
`open_material_changes`, `missing_prompt`, `missing_eval`, and
`missing_attested_eval`. Unprojected telemetry, including quarantined events,
blocks eligibility until projection completes. Active policy changes and risk or
control decisions are reflected without requiring new telemetry. Responses use
`Cache-Control: no-store`.

This is a read-only snapshot of known governance evidence, not a signed runtime
permit or proof that the deployed artifact matches `artifact_ref`. Integrators
must compare the artifact and scope and check again at the release boundary.
`norinth gate check --current` requires current eligibility and fails closed
against a server that does not supply it. Without that flag the CLI retains its
historical approval check. Both modes forward project/environment settings.

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

## Portable execution contracts (opt-in)

The `/v1/portable` namespace lets any execution platform use Norinth as an
online governance authority. It is separate from `/v1/events/batch`: telemetry
remains fail-open; portable authorization errors MUST stop the proposed effect.
Existing SDK event schemas, ingestion keys and approval APIs are unchanged.
Portable bodies accept `contract_version: "2026-01"` (the default) and reject
unknown fields. Machine keys do not grant human decision authority.

### Identities and stable bindings

A session-authorized administrator creates an integration with
`POST /api/portable/integrations`: name, namespace, explicit project and
environment, scopes, and optional action capabilities. The `nri_` credential
is returned once, stored only as a hash, and can be revoked.
`POST /api/portable/integrations/{id}/rotate` replaces the credential without
changing system IDs or evidence-source trust. The old credential stops working
immediately; revoked integrations cannot be revived by rotating. Every machine
request uses `Authorization: Bearer <nri_credential>`; tenancy and scope come
from that credential, never from a payload or a claimed user identity.
Scopes are `systems:read`, `systems:write`, `revisions:write`,
`observations:write`, `authorizations:request`, and `receipts:write`.
Every integration needs `systems:read` for its bound resources. Use a separate collector identity for independent
correction verification. Capabilities declare a name, resource type, operation,
primitive parameter types, reversibility and verification check ID; declarations
alone confer no execution permission.

`POST /v1/portable/systems` binds `(integration, project, environment,
resource_type, external_id)` to a stable server-generated ID. Display-name
changes preserve the binding and approval. Changing the stated purpose or
optional `legacy_application_name` returns the system to planned review.
A retired system cannot submit a new revision or obtain any permission.
Planned systems exist without production telemetry. Purpose must be declared
before a person approves the system.

### Immutable revisions and independent decisions

`POST /v1/portable/systems/{system_id}/revisions` submits a named immutable
manifest: artifact SHA-256, models, tools, resources, prompt references,
autonomy 0–4, and untrusted-input, sensitive-data, external-action and
human-checkpoint declarations. Norinth normalizes unique identifier lists,
computes `manifest_digest`, and returns the same record for an identical
resubmission. Reusing a revision name with different content returns `409`.
An artifact digest is the adapter's declaration; Norinth does not fetch or
verify the executable artifact. The adapter must enforce the reviewed digest
and report actual model/tool use through telemetry and observations.

People submit revisions through `POST /api/portable/submissions` using their
own Norinth session. The stored author is the authenticated actor; clients
cannot supply `submitted_by`. Machine submissions record the service identity.
`POST /api/portable/records/{id}/{decision}` records a rationale, requires
`expected_body_digest` (the returned record's `body_digest`) from the exact
record the reviewer read, and requires
an authorized independent actor. `approve_system` uses `review.decide`,
`approve_revision` uses `gate.decide`, policy/pack activation uses
`config.write`, and retirement uses `lifecycle.manage`. Authors cannot decide
their own work. A revision cannot be approved with failed, missing or stale
evidence or a policy violation. Decisions are immutable records linked to the
exact target and its body digest. Governance changes confer no authority until
the exact resulting state is anchored in Norinth's hash-chained audit log.
An audit failure leaves `audited_at` empty and permission indeterminate.
Authorized people can retry the audit through
`POST /api/portable/records/{id}/audit/retry`; the original decision and actor
are preserved. Machine records are retried through their idempotent contracts.

An embedded host can use Norinth's existing session/SSO through its backend.
If it needs a service to relay an exact human decision, a real session creates
`POST /api/portable/delegations` with integration, target, decision and
rationale. `/v1/portable/delegations/redeem` consumes the returned `nrd_` token
once within 60 seconds. The integration cannot change the decision or name a
user. Norinth rechecks active user, current permission, MFA enrollment policy,
scope, independence and the exact target body digest on redemption. Changing a
mutable system purpose after review or delegation issuance rejects approval
with `409`; the reviewer must refresh and make a new exact decision. This is a narrowly bound delegation,
not a general impersonation token.

### Current permission and online consumption

People draft per-system policies at
`POST /api/portable/systems/{id}/policies`; another authorized person activates
the immutable draft. Policy names exact allowed models, tools, resources,
runtime actions, corrective actions with exact preapproved parameters,
autonomy limits, checkpoint requirements, required checks, trusted evidence
sources, freshness and permit expiry. This policy is separate from the
existing organization's intake approval paths.

`POST /v1/portable/authorizations` accepts `revision_id`, `purpose`
(`release`, `runtime` or `remediation`), and an exact action for the latter two:
capability, resource ID and typed parameters. It returns an immutable
`authorization` record with `outcome`, reasons, system/revision/manifest digest,
policy ID/digest, checked time, evidence IDs, request digest, and
`enforcement: "executor_required"`. Outcomes are `allow`, `deny`,
`requires_review`, and `indeterminate`. Only `allow` returns an opaque `nrp_`
permit, expiring in 1–300 seconds. Historical approval does not imply a current
allow. Unknown evidence remains unknown; an empty allow-list permits nothing
in that category.

Immediately before the exact effect, the executor MUST call
`POST /v1/portable/authorizations/consume` with token and the complete original
request. Norinth re-evaluates current evidence, scope, system status and policy,
and consumes the permit atomically once. Expired, replayed, changed-request or
changed-policy permits are rejected. There is no offline verification or
cached permission fallback. Network errors, unknown results and non-allow
outcomes MUST stop the effect. A consumed permit proves that authorization was
checked, not that an executor intercepted every possible effect or executed
successfully. The check and external effect cannot be one database transaction;
the executor must consume immediately, preserve idempotency at the effect
boundary, and report outcomes honestly.

Routine releases require an explicit independently activated
`allow_routine_releases` policy. A successful reported release under that same
policy enables runtime permission for that exact revision while fresh evidence
and operating limits continue to pass; it does not rewrite the human approval
history. Replacing the policy invalidates this automatic release basis.
Remediation has a separate exact allow-list and preapproved parameters so a
bounded correction can run while the condition it must fix is failing.
It does not bypass system approval, resource scope, current policy or audit
requirements, and it never enables an ordinary runtime action by changing a
label.

### Observations, corrective outcomes, and recurrence

`POST /v1/portable/systems/{id}/observations` accepts external ID, check ID,
passing/failed/unknown result, timezone-qualified observation time,
`revision_digest` (the returned manifest digest), and an opaque evidence
reference. Observations are immutable and idempotent. Future observations are
rejected. Only active explicitly trusted sources can establish evidence.
For each check Norinth selects the latest observation for the exact revision;
a same-time failure wins over a pass. An older out-of-order pass cannot hide a
new failure. Missing, stale, unaudited or unknown observations do not pass.
Lookups are indexed and do not truncate to a recent-history window.

`POST /v1/portable/receipts` records authorization ID, executed/failed outcome
and evidence reference, only after this executor consumed permission. Receipts
cannot be rewritten. Reported releases have `reported_executed` status;
reported corrections remain `verification_pending`. Execution failure remains
`failed`. An independent source calls
`POST /v1/portable/receipts/{id}/verify` with an observation ID. That observation
must be owned by the authenticated source, trusted by the authorizing policy,
observed after execution, fresh, and bound to the exact system, manifest,
capability's verification check, request `action_digest`, and resource ID.
A pass marks the historical receipt verified; failure/unknown marks it failed.
The executor cannot verify its own receipt. Verification never silently accepts
a risk or closes a legacy finding. Later failed observations can deny current
eligibility and control assessments while the earlier verified receipt remains
historical evidence; new correction attempts need new permissions and receipts.

### Portable control packs and the standalone workspace

A session-authorized user imports a pack at
`POST /api/portable/control-packs?project=...&environment=...`; another person
activates it. Each immutable pack version declares trusted sources and controls:
ID, name, applicable resource types, check IDs, framework references and maximum
evidence age. Reusing a version with different content returns `409`.
`GET /api/portable/systems/{id}/controls?revision_id=...` reports each mapped
control as passing, failed, unknown or not applicable for this system and
revision only. Framework references are pack-maintainer mappings, not a
certification assertion or built-in complete NIST, ISO or SOC 2 coverage.
An organization must choose and validate its mappings and evidence collectors.
No framework coverage is inferred when no active pack is installed.

The standalone Connected systems workspace lists planned systems, current
release checks, immutable configuration, policy drafts, scoped integration
credentials, evidence, permission history, correction receipts and accountable
decisions. `/api/portable/systems`, `/api/portable/integrations`, and system
history accept bounded `limit`/`offset` pagination (history pages are 100).
The read-only live eligibility check issues no permit. A server-side adapter
can read the same snapshot at `GET /v1/portable/systems/{id}/workspace` and
control assessments at `GET /v1/portable/systems/{id}/controls?revision_id=...`
using only its scoped integration credential. These reads cannot record a
human decision or mint a permission; they allow a host to display current
status without creating unused permits. The Python client exposes `workspace`
and `controls` for this purpose. Frontend
`createPortableClient` takes an injected human-authenticated transport;
`PortableSystemWorkspace` takes that client, actor permissions and a source/
evidence link resolver. Hosts supply their own transport and URLs; the
components contain no execution-platform routes or cloud-provider types.
Framework packs and executor adapters stay external to the generic engine.

Legacy telemetry still works. A system can explicitly bind its old
`legacy_application_name` so unresolved findings, missing controls and open
changes in the exact project/environment also block permission; pending legacy
folds fail closed. The optional binding does not rename old event schemas or
pretend unrelated legacy applications share identity. Portable data and
credentials are included in tenant offboarding purge.

### Independent executor client

`norinth_logger.portable.PortableClient` is opt-in and synchronous, uses the
standard library, refuses redirects, and raises on transport errors. It is
independent of `NorinthClient` and its fail-open telemetry behavior:

```python
from norinth_logger.portable import PortableClient

runner = PortableClient("https://norinth.example.test", integration_token)
request = {"revision_id": exact_revision_id, "purpose": "release"}
grant = runner.authorize(request)
# consume raises for deny/review/indeterminate, missing permits and every error.
consumed = runner.consume(grant, request)
# Execute the exact previously registered artifact immediately, once, here.
# Persist the outcome even if reporting to Norinth needs a later retry.
runner.receipt(consumed["record_id"], outcome="executed", evidence_ref=execution_log_ref)
```

The client performs no effect itself and never asserts execution, artifact
identity or verification on behalf of the host. An executor should report a
failed outcome when its effect fails, and independently retry only delivery
of that same immutable receipt. It MUST NOT retry an external effect merely
because consumption or receipt delivery returned a network error.
