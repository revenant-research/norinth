# SDK Architecture

## Goal

Norinth starts as a logging SDK that helps governance teams build model inventory, runtime evidence, risk signals, and audit trails from engineering activity with minimal developer friction.

The first implementation proves the smallest useful loop:

1. A developer imports `norinth_logger`.
2. They initialize the SDK and enable auto-instrumentation.
3. The SDK instruments supported provider clients and FastAPI request context.
4. The SDK emits fail-open telemetry to the local platform.
5. The platform stores raw events, upserts normalized governance entities, maps evidence to configured controls/risk rules, detects material lifecycle changes, derives prompt release records, derives deployment approval gates, persists incident records, routes review work by configured roles, and serves dashboard/API views.

## SDK Layers

- Instrumentation: provider auto-instrumentation, FastAPI request context, decorators, and wrappers for fallback or advanced use.
- Context: trace IDs, span IDs, service, environment, project, system names, and governance context inferred from workflow arguments.
- Schema: versioned event payloads under `schema_version`.
- Privacy: metadata-only summaries and stable hashes by default.
- Transport: async batching to the platform with queue drops instead of application failure.

## Code Organization Standards

The repository is organized so new features extend existing modules rather than forcing rewrites.

### Python SDK

- `config.py`: SDK configuration and environment loading.
- `context.py`: trace context and inferred governance context.
- `client.py`: public client behavior and event creation.
- `autoinstrument.py`: provider method patching and FastAPI request-context middleware.
- `wrappers.py`: explicit client proxy fallback for unsupported integrations.
- `transport.py`: batching, send, fail-open behavior, and transport stats.
- `schemas.py`: SDK event schema.
- `privacy.py`: hashing, summaries, and context inference helpers.

New SDK primitives should add schema/event behavior in `client.py` and supporting instrumentation in a focused module. They should not require product workflow code to call explicit Norinth logging commands directly; when an explicit primitive is still necessary, it belongs behind an app-owned observability adapter.

### Demo Apps

- `demo-apps/support-copilot`: standalone OpenAI support workflow app.
- `demo-apps/claims-review-assistant`: standalone Anthropic claim review app.
- `demo-apps/agentic-governance-assistant`: standalone multi-provider app with retrieval, tool, guardrail, eval, and agent evidence.

Each demo app remains a separate service with its own `app/main.py`, settings, request/response schemas, provider integration code, and local `app/observability.py` adapter. The demo apps intentionally do not share application-layer provider wrappers or schemas, so they behave like separate customer applications that happen to install the same Norinth SDK. Direct SDK calls are isolated to each observability adapter; route handlers and workflow code use app-owned monitoring functions rather than depending on Norinth APIs directly.

### Platform

- `app/main.py`: FastAPI app construction only.
- `app/api/routes.py`: read APIs for dashboard/governance views.
- `app/ingestion/routes.py`: SDK ingestion endpoint.
- `app/storage/raw_events.py`: raw SDK event persistence.
- `app/storage/entities.py`: normalized governance entity tables and event processing.
- `app/storage/prompts.py`: prompt template and prompt version records derived from prompt release events.
- `app/storage/deployments.py`: deployment inventory, deployment versions, and approval gates derived from deployment events.
- `app/storage/incidents.py`: incident records derived from incident events and linked to trace, risk, control, and deployment evidence.
- `app/storage/governance_policy.py`: configured control catalogue, risk rules, control assessments, and risk findings.
- `app/storage/lifecycle.py`: application/workflow fingerprints, material change events, and review tasks.
- `app/storage/workflow.py`: users, role assignments, review queue policies, owner assignments, decisions, exceptions, and workflow status updates.
- `app/services/authorization.py`: local actor context authorization, role/scope checks, and bootstrap rules for protected governance mutations.
- `app/services/governance.py`: governance view services over events/entities.
- `app/dashboard/html.py`: dashboard shell.
- `app/schemas/events.py`: event and scope schemas.

New governance features should flow through ingestion, raw event storage, entity processing, governance policy assessment, lifecycle assessment, workflow state services, service functions, and API routes. Dashboard rendering can consume those APIs, but business logic should not live in dashboard HTML or route handlers.

## Event Types

The first slice emits:

- `trace.completed`: one workflow/function execution with latency, status, and function metadata.
- `model.call`: one AI provider/model interaction with provider, model, operation, usage, latency, and content summaries.
- `retrieval.call`: one retrieval operation with query/document metadata.
- `tool.call`: one tool operation with argument/result metadata.
- `guardrail.decision`: one guardrail decision with score and matched rules.
- `eval.result`: one evaluation score with threshold and pass/fail status.
- `agent.run`: one agent run summary with ordered steps and outcome.
- `prompt.event`: one prompt release event with prompt ID, version, owner, artifact, template summary/hash, and change notes.
- `deployment.event`: one deployment/version event with application, workflow, artifact, status, actor, provider/model, and prompt-version metadata.
- `incident.event`: one application-reported incident with severity, status, trace linkage, actor, provider/model, and metadata-only description.
- `sdk.health`: SDK operational health and fail-open evidence.

These events are enough to start building:

- AI application inventory.
- Model inventory.
- Vendor/provider inventory.
- Runtime audit trail.
- Trace-level monitoring.
- Basic error and usage reporting.
- Configured control assessments and risk findings from observed evidence.
- Material change detection and role-routed review tasks with due dates and escalation state.
- Prompt templates, prompt versions, and prompt release lineage.
- Deployment inventory, deployment versions, and approval gates that require linked prompt version and passing eval evidence for approval.
- Incident register entries linked to traces, risk/control evidence, deployments, owner assignments, and closure decisions.
- Owner assignments, governance decisions, and exception records.

## Fail-Open Contract

The SDK must not block customer code in normal observe mode. Transport errors, platform downtime, serialization issues, and queue pressure are SDK health issues, not product runtime failures.

Future `enforce` mode can intentionally block or alter behavior, but it must be opt-in and separate from the default logging path.

## Current Limits

This is not yet a policy engine or complete compliance workflow product. The platform now has API-managed standards-mapped control/risk configuration, prompt release lineage, material change review task generation, users, role assignments, queue routing, due dates, escalation state, protected governance mutations, deployment registry and approval gates with prompt/eval readiness checks, incident records with authorized closure, owner assignments, decisions, and exceptions, but governance maturity still requires production SSO/session management, full framework mappings, policy content, full incident-management workflow, and audit packet generation.
