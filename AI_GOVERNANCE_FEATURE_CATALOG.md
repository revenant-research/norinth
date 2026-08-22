# AI Governance Feature Catalogue

Feature set organized by governance category, with whether the current Norinth SDK and local platform can capture it directly, partially, or not at all today.

This file is a product truth document, not a roadmap promise. `Complete` means the local SDK/platform slice has a working, verified implementation for that evidence category. It does not mean the full enterprise governance workflow around that evidence is complete.

## SDK Capture Classes


| Capture class | Meaning                                                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Direct        | The SDK can emit first-party runtime evidence for this feature through current or clearly bounded instrumentation.                          |
| Partial       | The SDK can supply facts or evidence, but the platform still needs scoring, mapping, approval workflow, ownership, enrichment, or policies. |
| No            | The feature is primarily policy content, human workflow, regulatory intelligence, or external system data outside SDK runtime evidence.     |


## Reality Assessment

The SDK cannot, by itself, complete most AI governance application features. It can complete the **runtime evidence acquisition layer** for many of them. The platform still needs product data models, policy content, scoring rules, workflow state, reviewer actions, access control, reporting, and framework mappings.

The accurate product split is:


| Completion level | What the current SDK/platform slice can complete                                                                                                                                                | What still needs the application                                                                                                  |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| SDK-complete     | Capture FastAPI request traces, supported OpenAI/Anthropic model calls, manual retrieval/tool/guardrail/eval/agent events, SDK health, latency, status, token usage, hashes, and trace linkage. | Durable product entities, enterprise permissions, formal reports, review workflow, deployment workflow, and customer-ready UI.    |
| SDK-assisted     | Pre-fill inventory, dependency graph, structured risk signals, vendor usage, mapped runtime control evidence, audit trail, monitoring metrics, and basic portfolio views.                       | Human classification, approvals, ownership assignment, exception handling, and reviewer decisions.                                |
| App-owned        | Enterprise risk taxonomy, full control library, regulatory mappings, policy packs, legal/security/privacy workflows, vendor questionnaires, regulatory updates, audit packet generation.        | SDK can only provide supporting evidence; the platform now supports configurable control/risk foundations, not complete coverage. |


So when the table says `Direct`, it means **directly capturable as runtime evidence by SDK instrumentation**, not that the SDK alone produces a complete enterprise governance product feature.

## How The SDK Actually Completes Features

The SDK completes features by emitting a reliable event stream that the platform stores and derives into governance views. In the current implementation, FastAPI middleware captures request/workflow context, supported provider auto-instrumentation captures model calls, and explicit SDK primitives capture retrieval, tool, guardrail, eval, and agent evidence through app-owned observability adapters.


| SDK surface                    | Current status | What it emits                                                                                                                   | Governance features it enables                                                           |
| ------------------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `norinth.init()`               | Implemented    | SDK config, service name, project, environment, endpoint, SDK health event.                                                     | System registry, audit trail, SDK health visibility.                                     |
| `norinth.instrument_fastapi()` | Implemented    | Route/workflow name, request-scoped tenant/user/app/use-case metadata, latency, status, errors.                                 | AI system registry, application registry, audit trail, operational monitoring.           |
| `norinth.autoinstrument()`     | Implemented    | Provider/model call events from supported libraries, currently OpenAI Responses and Anthropic Messages.                         | Model registry, vendor inventory, runtime monitoring, usage evidence.                    |
| `norinth.retrieval()`          | Implemented    | Retriever name, query summary/hash, document summary/hash, document count, latency, status, trace linkage.                      | RAG evidence, source attribution foundation, dependency graph.                           |
| `norinth.tool_call()`          | Implemented    | Tool name, arguments summary/hash, result summary/hash, latency, status, trace linkage.                                         | Tool registry foundation, agent trace evidence, audit trail.                             |
| `norinth.guardrail()`          | Implemented    | Guardrail name, allow/warn/block decision, score, matched rules, trace linkage.                                                 | Guardrail evidence, policy-decision foundation, risk signals.                            |
| `norinth.eval_result()`        | Implemented    | Eval name, score, threshold, pass/fail, trace linkage.                                                                          | Evaluation evidence, quality signal foundation, release-gate evidence foundation.        |
| `norinth.agent_run()`          | Implemented    | Agent name, ordered steps, step count, outcome, latency, trace linkage.                                                         | Agent run trace, agent registry foundation, incident replay foundation.                  |
| `@norinth.trace()`             | Implemented    | Function identity, service, environment, request/user metadata when available, latency, status, errors.                         | Fallback/manual tracing for non-FastAPI or non-standard workflow code.                   |
| `norinth.model_call()`         | Implemented    | Provider, returned model ID, operation, prompt/response summary or hash, token usage, latency, status, errors.                  | Internal normalized event path used by provider instrumentation and manual integrations. |
| `norinth.prompt()`             | Implemented    | Prompt ID, version, application/workflow, artifact ref, owner, status, template summary/hash, change notes, and trace linkage.  | Prompt template registry, prompt version lineage, deployment gate evidence.              |
| `norinth.deployment()`         | Implemented    | Deployment ID, version, application/workflow, artifact ref, provider/model, prompt version, actor, and status.                  | Deployment registry, approval gate evidence, and material change review linkage.         |
| `norinth.incident()`           | Implemented    | Incident ID, title, severity, status, application/workflow, description summary/hash, actor, provider/model, and trace linkage. | Incident register, linked-trace evidence, ownership routing, and closure workflow.       |


That is the SDK’s real value: it turns code execution into governance records. Some records are automatic today; others require explicit SDK calls until broader library auto-instrumentation exists. It does **not** replace governance judgment, legal interpretation, formal approvals, or regulatory content.

## Engineering Friction Classes


| Friction class      | Meaning                                                                                                                          |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Auto-instrument     | Captured by patching supported model/client/framework libraries at startup with no changes inside business logic.                |
| Wrapper/decorator   | Requires adding a small decorator, context manager, or explicit SDK primitive around existing code.                              |
| Optional metadata   | Works without metadata, but becomes materially better if teams pass owner, purpose, data class, jurisdiction, etc.               |
| App workflow        | SDK can provide evidence, but the product feature needs workflow, reviewer, approval, or reporting logic in the app.             |
| Backend/integration | Requires server-side processing, external integrations, cloud discovery, SIEM, gateway, identity, or data warehouse connections. |
| Policy content      | Requires non-runtime content such as control libraries, regulatory mappings, risk taxonomies, or policy packs.                   |


## Current Implementation Status Classes


| Status      | Meaning                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------- |
| Complete    | Implemented in the current local SDK/platform slice using live telemetry, persisted events, and dashboard/API derivation. |
| Partial     | A working evidence foundation exists, but the feature is not complete as an enterprise governance capability.             |
| Not started | No meaningful implementation exists yet in the SDK/platform beyond catalogue/design notes.                                |


## Current Implemented SDK Surface

The current SDK implementation is intentionally narrow and verifiable:

- FastAPI request middleware captures request-scoped governance context.
- OpenAI Responses and Anthropic Messages are auto-instrumented.
- The SDK emits `trace.completed`, `model.call`, `retrieval.call`, `tool.call`, `guardrail.decision`, `eval.result`, `agent.run`, `prompt.event`, `deployment.event`, `incident.event`, and `sdk.health` events.
- The platform persists raw events, upserts normalized governance entities, maintains configured control/risk catalogues, evaluates control evidence requirements, persists control assessments and risk findings, detects material lifecycle changes, creates role-routed review tasks with due dates and escalation state, derives prompt templates/versions, derives deployment inventory/version/gate records, blocks deployment approval when prompt/eval evidence is missing, persists incident records linked to trace/risk/control/deployment evidence, generates ownership records from configured owner policies, enforces header-derived role authorization for governance mutations, records governance decisions, supports exceptions, and serves those records through APIs/dashboard views.
- Live verification proves these events with real provider calls, with direct SDK calls isolated behind app-owned observability adapters in each standalone demo app.

The SDK does **not** yet implement auto-instrumentation for RAG/vector databases, tools, MCP servers, eval frameworks, or guardrail libraries. The platform now has configurable standards-mapped control/risk foundations, prompt release lineage, material change detection, role/user configuration, routed review queues, authorization-enforced governance mutations, deployment registry/approval gates with prompt/eval readiness, incident records with closure decisions, ownership records, decision records, and exceptions. It does not yet implement production incident management, a full enterprise control library, legal/regulatory interpretation, production SSO/session management, or audit packet generation.

Latest live verification configured `9` controls, `5` risk rules, `5` owner policies, `2` users, `2` role assignments, and `1` review queue policy through protected platform APIs before telemetry ran. It also verified unauthorized configuration, owner assignment, review decision, exception, deployment gate approval, and incident closure attempts fail with `403`, and verified deployment approval fails with `400` when prompt/eval release evidence is missing. It then produced `28` events: `4` model calls, `3` prompt events, `4` deployment events, `1` incident event, `1` agent run, `1` retrieval, `1` tool call, `1` guardrail decision, `1` eval result, `1` error-status incident event, both `anthropic` and `openai` providers, `27` control assessments, `10` structured risk findings, `10` material changes, `10` review tasks with assignee and due date coverage, `3` prompt templates, `3` prompt versions, `3` deployments, `4` deployment versions, `4` deployment gates, `1` prompt-ready deployment gate, `1` incident record, `31` owner assignments, `3` authorized decisions, and `1` authorized active exception.

Current implementation status across the full catalogue:


| Status      | Count |
| ----------- | ----- |
| Complete    | 19    |
| Partial     | 48    |
| Not started | 40    |


## Current Platform Surface

The local platform stores every SDK event in the generic `sdk_events` table and also upserts normalized governance entity tables during ingestion.

Implemented entity tables:

- `governance_applications`
- `governance_workflows`
- `governance_models`
- `governance_providers`
- `governance_observed_events`
- `governance_risks`
- `governance_controls`
- `control_library`
- `risk_rules`
- `control_assessments`
- `risk_findings`
- `lifecycle_fingerprints`
- `change_events`
- `review_tasks`
- `platform_users`
- `role_assignments`
- `review_queue_policies`
- `prompt_templates`
- `prompt_versions`
- `governance_deployments`
- `deployment_versions`
- `deployment_approval_gates`
- `governance_incidents`
- `owner_assignments`
- `governance_decisions`
- `governance_exceptions`

The platform now maintains configured control definitions, risk rules, owner assignment policies, users, role assignments, review queue policies, prompt templates, prompt versions, deployments, deployment versions, approval gates, and incidents that map SDK event evidence to control assessments, risk findings, ownership records, routed review work, prompt/eval release readiness, deployment gate state, and incident closure decisions. It also fingerprints application/workflow shape, opens review tasks for detected material changes, assigns queue roles/users, calculates due dates and escalation state, enforces header-derived role authorization for governance mutations, records decisions with rationale, and supports exceptions with compensating controls and expiration. It still does not implement production SSO/session management, produce audit packets, maintain regulatory obligations, or provide full production incident management.

Implemented platform API/dashboard views:

- Summary counts.
- Application inventory.
- Workflow monitoring.
- Model and provider inventory.
- Agent runs.
- Retrieval evidence.
- Tool calls.
- Guardrail decisions.
- Evaluation results.
- Structured risk findings generated from configured risk rules and observed SDK evidence.
- Control catalogue and control assessments generated from configured evidence requirements.
- Material change events generated from lifecycle fingerprints.
- Review tasks generated from material changes, routed by role, assigned to configured users, and tracked with due dates plus escalation state.
- Prompt template and prompt version records linked to application/workflow release evidence.
- Deployment inventory, deployment versions, and approval gates linked to observed risks, control gaps, material changes, prompt version evidence, and passing eval evidence.
- Incident records linked to traces, observed risks, missing controls, deployment versions, deployment gates, owner routing, and authorized closure decisions.
- Users, role assignments, and review queue policies.
- Header-derived actor context and role/scope authorization for protected governance mutations.
- Owner assignment records for applications, risk findings, and missing controls.
- Governance decisions with target, actor, rationale, and status updates.
- Exceptions and waivers with compensating controls and expiration.
- SDK health.
- Resource graph.
- Detected systems.
- Recent raw events.

Current platform limitations:

- Risk findings are deterministic rule outputs with decision/exception support, not yet a full routed enterprise risk assessment workflow.
- Control assessments are mapped to configured controls, not a complete framework library.
- Review tasks can be routed, assigned, decided, escalated, and protected by local header-derived actor authorization; production SSO/session management is not implemented.
- Guardrails are logged decisions, not centralized enforcement.
- Eval results are logged scores, not managed test suites.
- Agent traces are step summaries, not full replay/debug traces with memory/tool payload expansion.
- There is no production identity provider integration, full incident-management workflow, or audit packet generation yet.

## Feature Table


| Category                           | Feature                                   | SDK Capture | Engineering Friction | Current Implementation Status | SDK/App Interpretation                                                                                                                                                                          |
| ---------------------------------- | ----------------------------------------- | ----------- | -------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AI Inventory / Registry            | AI system registry                        | Direct      | Auto-instrument      | Complete                      | Capture service, system, project, and environment from SDK config and request context.                                                                                                          |
| AI Inventory / Registry            | Model registry                            | Direct      | Auto-instrument      | Complete                      | Capture provider, returned model ID, operation, usage, status, and latency.                                                                                                                     |
| AI Inventory / Registry            | GenAI application registry                | Direct      | Auto-instrument      | Complete                      | Capture application name, route/workflow, use case, model purpose, and model calls from request context and provider telemetry.                                                                 |
| AI Inventory / Registry            | Agent registry                            | Direct      | Wrapper/decorator    | Partial                       | Capture agent run identity, step count, outcome, workflow, and trace linkage; ownership/autonomy classification is not implemented yet.                                                         |
| AI Inventory / Registry            | Vendor / third-party AI registry          | Direct      | Auto-instrument      | Complete                      | Infer provider/vendor from model calls and configured integrations.                                                                                                                             |
| AI Inventory / Registry            | Dataset registry                          | Partial     | Optional metadata    | Not started                   | Capture dataset IDs, hashes, labels, sensitivity metadata if developer provides them.                                                                                                           |
| AI Inventory / Registry            | Prompt/template registry                  | Direct      | Wrapper/decorator    | Complete                      | SDK prompt events create persisted prompt templates and versions with owner, artifact, application/workflow, template summary/hash, and release notes.                                          |
| AI Inventory / Registry            | Vector DB / RAG asset registry            | Direct      | Wrapper/decorator    | Partial                       | Capture retriever name, document count, source metadata, and trace linkage; vector DB auto-instrumentation is not implemented yet.                                                              |
| AI Inventory / Registry            | Tool / MCP tool registry                  | Direct      | Wrapper/decorator    | Partial                       | Capture tool names, arguments/result summaries, status, latency, and trace linkage; MCP auto-instrumentation is not implemented yet.                                                            |
| AI Inventory / Registry            | Deployment registry                       | Direct      | Optional metadata    | Complete                      | SDK deployment events create persisted deployment inventory and version records across instrumented applications.                                                                               |
| AI Inventory / Registry            | Business owner / technical owner          | Partial     | Optional metadata    | Partial                       | Platform generates owner assignment records and has configured users/roles with protected mutations; external identity integration is not implemented.                                          |
| AI Inventory / Registry            | Lifecycle status                          | Partial     | App workflow         | Partial                       | Active usage, material lifecycle changes, deployment status, and approval gates are inferred from events; retirement workflow is not implemented.                                               |
| AI Inventory / Registry            | Dependency graph                          | Direct      | Auto-instrument      | Partial                       | Current graph covers user, workflow, application, provider, model, trace, retriever, tool, guardrail, eval, and agent; dataset edges are not implemented.                                       |
| AI Inventory / Registry            | Shadow AI discovery                       | Partial     | Backend/integration  | Partial                       | Can discover instrumented usage; uninstrumented SaaS/cloud discovery needs integrations.                                                                                                        |
| Risk Register                      | AI-specific risk taxonomy                 | No          | Policy content       | Partial                       | Configured risk rules exist for provider dependency, missing controls, missing eval evidence, agentic trace gaps, and operational failures.                                                     |
| Risk Register                      | Inherent risk scoring                     | Partial     | App workflow         | Partial                       | SDK provides signals; platform now creates deterministic rule-based findings, but no full scoring questionnaire/workflow exists.                                                                |
| Risk Register                      | Residual risk scoring                     | Partial     | App workflow         | Not started                   | SDK captures mitigations/controls; app computes residual risk.                                                                                                                                  |
| Risk Register                      | Risk tiering                              | Partial     | App workflow         | Partial                       | SDK emits usage/context; app assigns tier based on governance rules.                                                                                                                            |
| Risk Register                      | Bias/fairness risk                        | Partial     | Optional metadata    | Not started                   | No bias/fairness eval is implemented yet; SDK eval events could carry those metrics later.                                                                                                      |
| Risk Register                      | Privacy risk                              | Direct      | Wrapper/decorator    | Partial                       | Current guardrail primitive captures sensitive-context decisions; formal PII detectors, data classes, and redaction actions are not implemented.                                                |
| Risk Register                      | Security risk                             | Direct      | Wrapper/decorator    | Partial                       | SDK now captures tool attempts and guardrail decisions; prompt injection/auth/policy violation detectors are not implemented.                                                                   |
| Risk Register                      | Hallucination risk                        | Partial     | Backend/integration  | Partial                       | SDK now captures eval results and retrieval context; no hallucination or groundedness checker is implemented.                                                                                   |
| Risk Register                      | Operational reliability risk              | Direct      | Auto-instrument      | Complete                      | Capture latency, errors, provider failures, and usage from observed model calls.                                                                                                                |
| Risk Register                      | Human oversight risk                      | Partial     | App workflow         | Partial                       | Review tasks, reviewer assignment, due dates, escalation state, authorization-protected decisions, and exceptions exist; adequacy scoring is not implemented.                                   |
| Risk Register                      | Third-party opacity risk                  | Partial     | App workflow         | Partial                       | Capture vendor/model usage; questionnaire evidence needs app workflow.                                                                                                                          |
| Risk Register                      | Mitigation tracking                       | Partial     | App workflow         | Partial                       | Capture runtime mitigations and route ownership/review work; remediation plans and closure evidence remain app workflow.                                                                        |
| Risk Register                      | Incident-linked risk updates              | Direct      | Wrapper/decorator    | Partial                       | Incident events create persisted incident records linked to open risk findings, missing controls, trace evidence, and deployment evidence; automatic risk rescoring is not implemented.         |
| Compliance / Framework Mapping     | EU AI Act mapping                         | Partial     | Policy content       | Not started                   | SDK emits evidence; app maps evidence to obligations.                                                                                                                                           |
| Compliance / Framework Mapping     | NIST AI RMF mapping                       | Partial     | Policy content       | Partial                       | Configured controls and risk rules include selected NIST AI RMF references; complete framework mapping is not implemented.                                                                      |
| Compliance / Framework Mapping     | ISO 42001 mapping                         | Partial     | Policy content       | Partial                       | Configured controls can include selected ISO/IEC 42001 references; management-system workflows are not implemented.                                                                             |
| Compliance / Framework Mapping     | SOC 2 / HIPAA / GDPR evidence             | Partial     | Policy content       | Partial                       | SDK captures logging/operational evidence and configured controls can reference SOC 2 logging; HIPAA/GDPR-specific mappings are not implemented.                                                |
| Compliance / Framework Mapping     | Control library                           | No          | Policy content       | Partial                       | Platform-managed runtime-evidence control definitions exist; full enterprise framework coverage is not implemented.                                                                             |
| Compliance / Framework Mapping     | Policy packs                              | No          | Policy content       | Not started                   | Policy packs are app content; SDK policy enforcement is not implemented yet.                                                                                                                    |
| Compliance / Framework Mapping     | Compliance scoping                        | Partial     | Optional metadata    | Partial                       | SDK captures tenant, application, use case, and model purpose; jurisdiction/data class are not captured yet.                                                                                    |
| Compliance / Framework Mapping     | Obligation mapping                        | Partial     | Policy content       | Not started                   | App maps SDK facts to jurisdiction/framework obligations.                                                                                                                                       |
| Compliance / Framework Mapping     | Gap analysis                              | Partial     | App workflow         | Partial                       | Platform now marks configured controls as passing or missing from SDK evidence; workflow remediation and exception handling are only partially implemented.                                     |
| Compliance / Framework Mapping     | Regulatory update monitoring              | No          | Backend/integration  | Not started                   | Requires regulatory intelligence outside SDK runtime.                                                                                                                                           |
| Workflow / Review / Approval       | Use case intake                           | Partial     | App workflow         | Partial                       | SDK can auto-create draft inventory; human intake remains app workflow.                                                                                                                         |
| Workflow / Review / Approval       | Risk assessment workflow                  | Partial     | App workflow         | Partial                       | SDK pre-fills signals; platform can route review tasks and persist decisions, but full assessment questionnaires/scoring are not implemented.                                                   |
| Workflow / Review / Approval       | Vendor review workflow                    | Partial     | App workflow         | Partial                       | SDK proves vendor usage; questionnaire/review is app workflow.                                                                                                                                  |
| Workflow / Review / Approval       | Legal/privacy/security reviews            | No          | App workflow         | Not started                   | Human review orchestration belongs to app.                                                                                                                                                      |
| Workflow / Review / Approval       | Deployment approval gates                 | Partial     | Backend/integration  | Partial                       | Deployment events create approval gates tied to risks, missing controls, material changes, prompt release evidence, and passing eval evidence; runtime blocking enforcement is not implemented. |
| Workflow / Review / Approval       | Periodic review                           | Partial     | App workflow         | Not started                   | SDK supplies ongoing facts; app schedules and tracks review tasks.                                                                                                                              |
| Workflow / Review / Approval       | Material change review                    | Direct      | Auto-instrument      | Partial                       | Platform fingerprints app/workflow shape, creates review tasks, routes them to configured roles/users, calculates due/escalation state, and protects decisions by role/scope.                   |
| Workflow / Review / Approval       | Approval history                          | Partial     | App workflow         | Partial                       | Governance decisions are persisted with authenticated actor, target, rationale, and timestamp; production identity integration is not implemented.                                              |
| Workflow / Review / Approval       | Decision rationale                        | Partial     | Optional metadata    | Partial                       | Decision APIs persist rationale for review tasks, risk findings, change events, and control assessments.                                                                                        |
| Runtime Monitoring / Observability | Request-level logging                     | Direct      | Auto-instrument      | Complete                      | FastAPI middleware captures trace ID, user/request metadata, route/workflow, status, latency, and timestamps.                                                                                   |
| Runtime Monitoring / Observability | Prompt and output logging                 | Direct      | Auto-instrument      | Complete                      | Capture prompt and response summaries/hashes by default, with opt-in raw content capture.                                                                                                       |
| Runtime Monitoring / Observability | Model/provider tracking                   | Direct      | Auto-instrument      | Complete                      | Capture provider, returned model ID, operation, status, and usage for supported clients.                                                                                                        |
| Runtime Monitoring / Observability | Latency/errors/retries                    | Direct      | Auto-instrument      | Complete                      | Capture timings, exceptions, and status; retry count is not separately modeled yet.                                                                                                             |
| Runtime Monitoring / Observability | Token usage and cost                      | Direct      | Auto-instrument      | Partial                       | Capture input/output tokens from provider responses; provider cost calculation is not implemented yet.                                                                                          |
| Runtime Monitoring / Observability | Throughput and usage                      | Direct      | Auto-instrument      | Complete                      | Aggregate traces by model, app, tenant, provider, workflow, and observed usage.                                                                                                                 |
| Runtime Monitoring / Observability | Data/prediction/embedding drift           | Partial     | Backend/integration  | Not started                   | Distribution/embedding capture and drift computation are not implemented yet.                                                                                                                   |
| Runtime Monitoring / Observability | Model quality metrics                     | Partial     | Optional metadata    | Partial                       | SDK emits eval result events; ground truth datasets and formal quality metrics are not implemented yet.                                                                                         |
| Runtime Monitoring / Observability | Feature quality                           | Partial     | Optional metadata    | Not started                   | Feature-stat capture for ML paths is not implemented yet.                                                                                                                                       |
| Runtime Monitoring / Observability | Traffic anomalies                         | Direct      | Backend/integration  | Not started                   | Event time series exist, but anomaly detection is not implemented yet.                                                                                                                          |
| Runtime Monitoring / Observability | Incident replay                           | Direct      | Auto-instrument      | Partial                       | Incident records link to trace IDs and related model/tool/retrieval/eval/agent evidence; full replay UI with expanded event timelines is not implemented yet.                                   |
| Guardrails / Policy Enforcement    | Runtime policy checks                     | Direct      | Backend/integration  | Not started                   | Runtime policy engine integration is not implemented yet.                                                                                                                                       |
| Guardrails / Policy Enforcement    | PII/sensitive data detection              | Direct      | Wrapper/decorator    | Partial                       | Current demo logs a sensitive-context guardrail decision; formal PII detector, redaction, and masking are not implemented.                                                                      |
| Guardrails / Policy Enforcement    | Prompt injection detection                | Direct      | Auto-instrument      | Not started                   | Detector library integration is not implemented; current guardrail primitive can log decisions from a configured detector.                                                                      |
| Guardrails / Policy Enforcement    | Toxicity/hate/abuse checks                | Direct      | Backend/integration  | Not started                   | Safety classifier integration is not implemented yet.                                                                                                                                           |
| Guardrails / Policy Enforcement    | Hallucination/groundedness checks         | Partial     | Backend/integration  | Partial                       | SDK can emit eval results; groundedness checker integration is not implemented yet.                                                                                                             |
| Guardrails / Policy Enforcement    | Tool/model/provider allowlists            | Direct      | Optional metadata    | Not started                   | Allowlist configuration and enforcement are not implemented yet.                                                                                                                                |
| Guardrails / Policy Enforcement    | Budget/rate limit enforcement             | Partial     | Backend/integration  | Partial                       | SDK reports token usage; budget/rate-limit enforcement needs server or gateway logic.                                                                                                           |
| Guardrails / Policy Enforcement    | Human-in-the-loop escalation              | Partial     | App workflow         | Not started                   | Pause/request-approval behavior and escalation queues are not implemented yet.                                                                                                                  |
| Guardrails / Policy Enforcement    | Block/allow/warn decisions                | Direct      | Wrapper/decorator    | Partial                       | SDK captures allow/warn/block-style guardrail decisions; central policy enforcement is not implemented yet.                                                                                     |
| Agent Governance                   | Agent run trace                           | Direct      | Wrapper/decorator    | Complete                      | Capture agent name, ordered steps, model/tool/retrieval/eval references, outcome, latency, and trace linkage.                                                                                   |
| Agent Governance                   | Autonomy classification                   | Partial     | App workflow         | Not started                   | SDK captures tool/approval behavior; app classifies unless configured.                                                                                                                          |
| Agent Governance                   | Tool permissions                          | Direct      | Wrapper/decorator    | Partial                       | SDK captures attempted tools; configured permission policy and enforcement are not implemented yet.                                                                                             |
| Agent Governance                   | MCP server/tool logging                   | Direct      | Auto-instrument      | Not started                   | MCP server/tool auto-instrumentation is not implemented yet.                                                                                                                                    |
| Agent Governance                   | Multi-agent lineage                       | Direct      | Wrapper/decorator    | Not started                   | Parent/child agent run relationships are not implemented yet.                                                                                                                                   |
| Agent Governance                   | Emergent behavior detection               | Partial     | Backend/integration  | Not started                   | SDK emits traces; app/evals detect behavior patterns.                                                                                                                                           |
| Agent Governance                   | Tool selection evals                      | Partial     | Optional metadata    | Partial                       | SDK emits eval result events; tool-selection-specific evaluator logic is not implemented yet.                                                                                                   |
| Vendor / Third-Party AI Risk       | Vendor inventory                          | Direct      | Auto-instrument      | Complete                      | Infer vendors/providers from runtime usage.                                                                                                                                                     |
| Vendor / Third-Party AI Risk       | Vendor questionnaire                      | No          | App workflow         | Not started                   | Questionnaires are app workflow; SDK can pre-fill usage evidence.                                                                                                                               |
| Vendor / Third-Party AI Risk       | Training data questions                   | Partial     | Optional metadata    | Not started                   | SDK captures dataset metadata if supplied.                                                                                                                                                      |
| Vendor / Third-Party AI Risk       | Vendor transparency gaps                  | Partial     | App workflow         | Not started                   | App compares vendor facts/questionnaire against required fields.                                                                                                                                |
| Vendor / Third-Party AI Risk       | Ongoing vendor monitoring                 | Direct      | Auto-instrument      | Partial                       | Capture vendor/model usage and errors over time; violations and cost calculations are not implemented yet.                                                                                      |
| Vendor / Third-Party AI Risk       | Embedded SaaS AI tracking                 | Partial     | Backend/integration  | Partial                       | SDK tracks instrumented SaaS/API calls; browser/cloud discovery needs integrations.                                                                                                             |
| Documentation / Audit Evidence     | AI factsheets                             | Partial     | App workflow         | Not started                   | SDK supplies facts; app generates formal factsheet document.                                                                                                                                    |
| Documentation / Audit Evidence     | Model cards / agent cards                 | Partial     | App workflow         | Not started                   | SDK supplies usage, lineage, and eval evidence; card generation is not implemented yet.                                                                                                         |
| Documentation / Audit Evidence     | Risk assessment reports                   | Partial     | App workflow         | Not started                   | SDK supplies evidence; app owns assessment narrative/scoring.                                                                                                                                   |
| Documentation / Audit Evidence     | Control evidence                          | Direct      | Auto-instrument      | Complete                      | Runtime events provide timestamped evidence for model calls, traces, SDK health, retrievals, tools, guardrails, evals, and agent runs.                                                          |
| Documentation / Audit Evidence     | Audit trail                               | Direct      | Auto-instrument      | Complete                      | Capture persisted trace/model-call event stream with actor metadata when present and timestamps.                                                                                                |
| Documentation / Audit Evidence     | Change logs                               | Direct      | Auto-instrument      | Partial                       | Material change events are persisted with previous/current fingerprints and changed fields; deployment/config change logs are not implemented yet.                                              |
| Documentation / Audit Evidence     | Audit packet                              | Partial     | App workflow         | Not started                   | SDK supplies evidence; app packages final audit artifact.                                                                                                                                       |
| Testing / Evaluation               | Pre-deployment testing                    | Partial     | Backend/integration  | Not started                   | SDK can emit eval results, but CI/test suite integration is not implemented yet.                                                                                                                |
| Testing / Evaluation               | Bias/fairness testing                     | Partial     | Optional metadata    | Not started                   | Bias/fairness evaluator, protected attributes, and thresholds are not implemented yet.                                                                                                          |
| Testing / Evaluation               | Robustness/red-team testing               | Partial     | Backend/integration  | Not started                   | Robustness/red-team test orchestration is not implemented yet.                                                                                                                                  |
| Testing / Evaluation               | Prompt injection testing                  | Direct      | Auto-instrument      | Not started                   | Prompt-injection detector/eval integration is not implemented yet.                                                                                                                              |
| Testing / Evaluation               | Hallucination and groundedness evals      | Partial     | Backend/integration  | Partial                       | SDK emits eval result events and retrieval context; groundedness evaluator integration is not implemented yet.                                                                                  |
| Testing / Evaluation               | LLM-as-judge evaluations                  | Partial     | Backend/integration  | Not started                   | Judge orchestration and judge configuration are not implemented yet.                                                                                                                            |
| Testing / Evaluation               | Regression tests for model/prompt changes | Partial     | Backend/integration  | Not started                   | Model/prompt change detection and regression gates are not implemented yet.                                                                                                                     |
| Explainability / Transparency      | Local/global explanations                 | Partial     | Optional metadata    | Not started                   | Explainer output capture is not implemented yet.                                                                                                                                                |
| Explainability / Transparency      | SHAP/LIME/integrated gradients            | Partial     | Optional metadata    | Not started                   | Explainability library integrations are not implemented yet.                                                                                                                                    |
| Explainability / Transparency      | Decision explanations                     | Partial     | Optional metadata    | Not started                   | Explanation text/metadata capture is not implemented as a distinct feature yet.                                                                                                                 |
| Explainability / Transparency      | RAG source attribution                    | Direct      | Wrapper/decorator    | Partial                       | Capture retrieved document IDs/count/source metadata and trace linkage; citation extraction and vector DB auto-instrumentation are not implemented.                                             |
| Explainability / Transparency      | Prompt/response trace                     | Direct      | Auto-instrument      | Complete                      | Capture prompt summary/hash or raw content when enabled, response summary/hash, response metadata, and trace linkage.                                                                           |
| Explainability / Transparency      | Data provenance                           | Partial     | Optional metadata    | Partial                       | Retrieval events capture request-derived source metadata; full dataset/source provenance is not implemented yet.                                                                                |
| Portfolio / Executive Reporting    | AI portfolio dashboard                    | Partial     | App workflow         | Complete                      | Current dashboard renders live SDK-derived inventory, usage, model, provider, workflow, agent, tool, retrieval, guardrail, eval, and basic risk/control views.                                  |
| Portfolio / Executive Reporting    | Risk heatmaps                             | Partial     | App workflow         | Not started                   | SDK feeds signals; app scores and visualizes risk.                                                                                                                                              |
| Portfolio / Executive Reporting    | Compliance readiness                      | Partial     | App workflow         | Not started                   | SDK feeds evidence; app computes readiness.                                                                                                                                                     |
| Portfolio / Executive Reporting    | Open reviews / overdue reviews            | No          | App workflow         | Complete                      | Open material-change review tasks are generated, role-routed, assigned where a matching user exists, given due dates, and marked unassigned/on-track/overdue/escalated.                         |
| Portfolio / Executive Reporting    | Control gaps                              | Partial     | App workflow         | Partial                       | Configured controls now produce passing/missing assessments from SDK evidence; full remediation workflow and executive readiness scoring are not implemented.                                   |
| Portfolio / Executive Reporting    | Policy violations                         | Direct      | Auto-instrument      | Not started                   | Policy decision/violation event model and policy engine integration are not implemented yet.                                                                                                    |
| Portfolio / Executive Reporting    | Incidents                                 | Direct      | Wrapper/decorator    | Partial                       | SDK incident events create persisted incident records shown in the dashboard with severity, status, linked evidence, owner routing, and authorized closure.                                     |
| Portfolio / Executive Reporting    | Usage, cost, ROI                          | Direct      | Optional metadata    | Partial                       | SDK captures usage; cost and ROI/business value calculations are not implemented yet.                                                                                                           |


