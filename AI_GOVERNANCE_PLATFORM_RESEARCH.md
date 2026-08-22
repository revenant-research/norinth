# AI Governance Platform Research

Research date: 2026-05-06

This report reviews 12 AI governance and governance-adjacent platforms through the lens Norinth needs most: real UI/UX surfaces, workflow models, governance object models, evidence automation, and where an SDK-first platform can credibly differentiate.

The findings are based on public product pages, documentation, help centers, and product workflow docs. Where a vendor page makes a claim without showing a documented workflow or UI behavior, this report labels it as a claim rather than observed product behavior.

## Executive Read

Serious AI governance products do not present a single generic dashboard. They are organized around governed objects and workflow state:

- Registries for AI systems, models, agents, datasets, prompts, vendors, tools, and deployments.
- Object detail pages that show ownership, purpose, lifecycle, risk tier, controls, evidence, decisions, and activity.
- Review queues and approval workflows with assigned roles, due dates, status transitions, attestations, and audit trails.
- Evidence stores that connect runtime telemetry, tests, documents, policy controls, and human decisions.
- Runtime monitoring surfaces with trace drilldowns, alerts, eval results, guardrail violations, and incident response.
- Executive dashboards that summarize portfolio posture but do not replace the operational workflows.

Norinth is directionally aligned on the evidence layer. The current SDK/platform already captures runtime events, model calls, agent runs, retrieval/tool/guardrail/eval evidence, prompt releases, deployments, incidents, controls, risks, review tasks, decisions, exceptions, and ownership records. The main gap is productization: Norinth needs object-first UI, workflow state machines, configurable policy/control libraries, audit packet generation, and production identity/permissions to look like enterprise AI governance software rather than telemetry tables.

## Platform Profiles

### Credo AI

Primary positioning: Enterprise AI governance control plane for AI systems, models, applications, and agents.

Observed workflow and UI surfaces:

- Credo's product page positions the platform around discovery, assessment, governance, monitoring, and reporting for agents, models, and applications.
- The platform modules are presented as AI Registry and Discovery, Risk Intelligence, Compliance and Policy Engine, and Runtime Governance.
- The public pycredoai SDK documentation shows a concrete workflow model: workflow stages define the governance pipeline, and each use case has a current stage plus current step. Step progression is `assessment -> evidence_collection -> clear`, with a terminal `rejected` path.
- The product page describes Agent Registry, Agent Cards, dependency graphs, trace ingestion, continuous evaluation, human-in-the-loop escalation, and remediation agents.

Governance object model:

- Use cases, AI systems, agents, models, apps, tools, data sources, guardrails, policy packs, controls, risk assessments, incidents, evidence, and workflow stages.

Automation approach:

- Connectors across cloud, AI ops, GRC, InfoSec, Dev/MLOps, and agent platforms.
- Runtime trace ingestion and continuous evaluation are positioned as key agentic AI governance capabilities.
- Policy packs map regulatory frameworks to controls and evidence.

Maturity signals:

- Strongest public evidence is the documented workflow API and clear lifecycle vocabulary.
- Product claims around GAIA and remediation agents are strategically important but less verifiable from public UI docs.

Norinth implications:

- Norinth needs a first-class `UseCase` or `AIApplication` object detail page with workflow stage and step, not only derived summary rows.
- Norinth's agent/event graph should become a visible dependency graph: app -> workflow -> provider/model -> prompt -> tool -> retrieval source -> guardrail/eval -> deployment -> incident.

Sources:

- [Credo AI product](https://www.credo.ai/product)
- [Credo AI workflow SDK docs](https://docs.sdk.credo.ai/core-concepts/workflow)
- [Credo AI audit artifacts](https://www.credo.ai/solutions/artifacts)

### Holistic AI

Primary positioning: End-to-end AI governance platform for discovery, risk testing, compliance, and policy enforcement.

Observed workflow and UI surfaces:

- Holistic AI organizes the product around Identify, Protect, and Enforce.
- Public product pages emphasize shadow AI discovery, centralized inventory, configurable risk and compliance workflows, automated testing, continuous monitoring, compliance assessments, and enterprise integrations.
- The platform introduces Guardian Agents, split into Sentinel Agents that watch and alert, and Operative Agents that act and enforce.

Governance object model:

- AI systems, models, agents, APIs, pipelines, risks, tests, compliance assessments, policies, approval processes, and enforcement actions.

Automation approach:

- The product claims continuous monitoring and intervention by Guardian Agents.
- Enforce capabilities include real-time intervention such as kill switches, unsafe request blocking, privilege revocation, and remediation.

Maturity signals:

- The public product story is coherent around Identify/Protect/Enforce.
- Specific UI workflows are less documented publicly than Credo, Saidot, ValidMind, Fiddler, Arize, or Giskard.

Norinth implications:

- Norinth should separate observe-only evidence from any future enforce mode. The current fail-open contract is correct.
- Runtime policy actions, if added, need to be explicit, opt-in, and visibly distinct from monitoring evidence.

Sources:

- [Holistic AI governance platform](https://www.holisticai.com/ai-governance-platform)
- [Holistic AI learn center](https://www.holisticai.com/learn)
- [Holistic AI inventory](https://www.holisticai.com/ai-inventory)

### IBM watsonx.governance

Primary positioning: Enterprise governance for AI assets, model lifecycle, risk, regulatory compliance, and monitoring.

Observed workflow and UI surfaces:

- IBM documentation describes AI use cases managed inside inventories.
- Use cases are lifecycle objects that can be searched and filtered and can be scoped to different inventories.
- Documentation and product pages describe model inventory dashboards, model health monitors, risk scores, compliance workflows, and Regulatory Compliance Management master dashboards.
- Roles include Admins, Editors, and Viewers for collaborative governance.

Governance object model:

- AI use cases, inventories, assets, models, deployments, risk scores, regulatory mandates, controls, compliance tasks, monitoring metrics, and reports.

Automation approach:

- Integration with watsonx and broader IBM governance tooling.
- Monitors for fairness, drift, quality, toxic language, PII, and model health.
- Regulatory Compliance Management links use cases to regulatory obligations and control effectiveness.

Maturity signals:

- Strong enterprise lifecycle and inventory framing.
- IBM's governance story is mature in regulated enterprise terms, but public docs are fragmented across product areas.

Norinth implications:

- Norinth's dashboard should support multiple inventories or portfolio scopes, not only a global tenant view.
- Control effectiveness and model risk posture should be separate top-level views, not buried under raw event counts.

Sources:

- [IBM creating and managing AI use cases](https://dataplatform.cloud.ibm.com/docs/content/wsj/analyze-data/xgov-use-cases.html?context=wx&locale=en)
- [IBM watsonx.governance overview](https://www.ibm.com/docs/en/watsonx/w-and-w/2.0.0?topic=governing-ai-assets)
- [IBM Regulatory Compliance Management](https://dataplatform.cloud.ibm.com/docs/content/svc-watsonxgov/wxgov_rcm_desc.html?context=wx)

### OneTrust AI Governance

Primary positioning: AI governance program center that translates AI risk into enforceable controls.

Observed workflow and UI surfaces:

- OneTrust frames the workflow as Catalog AI Systems and Assess Risk, Monitor Posture Across Platforms, and Programmatically Enforce Controls.
- The product page explicitly lists central inventory for models, datasets, agents, and vendors; ownership and lifecycle status; component dependencies; framework templates; configurable intake and approval workflows; attestations; signoff tracking; automated evidence; and audit outputs.
- Monitoring surfaces include drift, quality, safety, performance monitoring, telemetry ingestion, policy violations, PII/sensitive attribute detection, and in-app alerts.
- Enforcement surfaces include prompt/output filtering, block/allow policy actions, required evaluations before production, runtime guardrails, and re-review on material changes.

Governance object model:

- Models, datasets, agents, vendors, systems, components, owners, lifecycle states, risks, controls, attestations, signoffs, policy violations, evaluations, and approvals.

Automation approach:

- Policy-driven controls, telemetry ingestion, runtime guardrails, data/pipeline policies, MCP policy enforcement, and audit logs.

Maturity signals:

- The product page is unusually specific about lifecycle features and enforcement mechanics.
- Detailed UI screenshots are less public, but workflow nouns are mature and enterprise-oriented.

Norinth implications:

- Norinth already implemented prompt/eval deployment gate readiness and material change review tasks; those should become explicit UI workflows with queues, approvals, attestation state, and re-review triggers.
- MCP/tool governance should become first-class as Norinth expands tool instrumentation.

Sources:

- [OneTrust AI Governance](https://www.onetrust.com/content/onetrust/us/en/solutions/ai-governance)
- [OneTrust AI Governance demo page](https://www.onetrust.com/resources/onetrust-ai-governance-demo-video/)
- [OneTrust AI Governance announcement](https://onetrust.com/news/onetrust-introduces-ai-governance-solution)

### ModelOp Center

Primary positioning: AI lifecycle management and governance control tower for all enterprise AI.

Observed workflow and UI surfaces:

- ModelOp presents a clear six-step lifecycle: Submit a New AI Use Case, Assess Risk Based on Policy, Implement the AI Solution, Conduct Testing, Review and Deploy, Continuously Monitor and Review.
- Public documentation lists example governance workflows for use case registration, model implementations, LLM implementations, vendor implementations, basic deployment, and annual review.
- Product pages emphasize self-service role-based workflows, an AI system of record, automated controls, testing, documentation, model cards, deployment tracking, annual attestations, notifications, alerts, and dashboards.

Governance object model:

- AI use cases, internal solutions, vendor solutions, model implementations, LLM implementations, deployments, tests, controls, policies, model cards, evidence, reviews, attestations, and monitoring records.

Automation approach:

- Workflow orchestration across enterprise systems.
- Policy-driven controls based on risk tier, geography, model type, and governance requirements.
- Automated testing and documentation generation.

Maturity signals:

- Strongest operational workflow structure in public materials.
- The six-step lifecycle is a useful benchmark for Norinth product navigation.

Norinth implications:

- Norinth should adopt a lifecycle-first navigation spine: Intake, Assess, Build Evidence, Review, Deploy, Monitor, Respond.
- The dashboard should surface bottlenecks, SLA breaches, pending approvals, and annual/periodic review status, not only inventory counts.

Sources:

- [ModelOp product](https://www.modelop.com/product)
- [ModelOp example governance workflows](https://modelopdocs.atlassian.net/wiki/spaces/dv33/pages/2115960853/Example+Governance+Workflows)
- [ModelOp controls](https://www.modelop.com/ai-governance-software/controls)

### Monitaur

Primary positioning: AI governance platform for policy-to-proof governance across model ecosystems.

Observed workflow and UI surfaces:

- Monitaur organizes the platform into Define, Manage, and Automate.
- Manage includes complete inventory, common controls, collaborative workflows, and vendor governance.
- Automate includes FlightSim for pre-deployment evaluation and Record for continuous production validation.
- The platform claims decision logs, drift and bias validation, safe ranges, risk-aligned events, common controls mapping, and audit-ready proof.

Governance object model:

- Business use cases, models, vendors, controls, policies, validation records, decision logs, safe ranges, evidence, and model performance records.

Automation approach:

- Pre-deployment simulation.
- Continuous production validation.
- Evidence automation mapped to common controls.
- Integrations and client libraries to connect existing modeling and MLOps tools.

Maturity signals:

- Clear policy-to-proof story with strong focus on evidence automation.
- Public materials are more product narrative than detailed UI docs.

Norinth implications:

- Norinth's strongest differentiation can be "proof from runtime" rather than just registry management.
- Current control evidence should evolve into an evidence store with provenance, evidence type, control mapping, collection method, freshness, and reviewer disposition.

Sources:

- [Monitaur platform](https://www.monitaur.ai/platform)
- [Monitaur AI governance](https://monitaur.ai/ai-governance)
- [Monitaur vendor governance](https://info.monitaur.ai/monitaur-vendor-governance)

### ValidMind

Primary positioning: Enterprise model risk management, validation, documentation, and workflow governance.

Observed workflow and UI surfaces:

- ValidMind documentation shows a customizable inventory with record types, search, filter, sort, active filter chips, saved per-user layout, custom fields, stakeholders, and configurable overview pages.
- Filtering supports nested rule groups and AND/OR logic, with field-specific operators and entity selectors.
- Workflow documentation describes model stages, workflow steps/states, active workflow tracking, workflow history, validation reports, findings, attestations, and model activity logs.
- Organizational oversight surfaces include model activity covering inventory updates, stage transitions, documentation changes, test results, and findings.

Governance object model:

- Inventory records, models, custom fields, stakeholders, stages, workflows, validations, reports, findings, artifacts, attestations, and activity events.

Automation approach:

- Workflow configuration, validation report generation, evidence/artifact management, and documentation support.

Maturity signals:

- Strong public docs for concrete UI mechanics, especially inventory filtering and configurable layouts.
- This is a strong reference for enterprise-grade table/detail UX.

Norinth implications:

- Norinth needs configurable inventory views, filters, saved layouts, custom fields, and activity timelines.
- The current resource graph and dashboard rows should be backed by object pages with field history and activity.

Sources:

- [ValidMind inventory docs](https://docs.validmind.ai/guide/model-inventory/working-with-model-inventory.html)
- [ValidMind model validation](https://docs.validmind.ai/guide/model-validation/managing-model-validation.html)
- [ValidMind oversight and reporting](https://docs.validmind.ai/training/administrator-fundamentals/organizational-oversight-reporting.html)

### Saidot

Primary positioning: AI governance platform using a knowledge graph, catalogues, risk inheritance, controls, and automations.

Observed workflow and UI surfaces:

- Saidot has an Automations view with active automations, monthly executions, success rate, and time saved.
- Automation templates include classify system by EU AI Act, inherit risks for linked items, lifecycle stage approvals, inherit risk level from linked items, and inherit controls to existing risks.
- The AI Act workflow is documented as a stepwise process: trigger classification, answer classifier questions, save provisional classification as draft, review justification, create review task for legal/compliance, apply draft classification, and generate policy/control tasks.
- The control catalogue exposes metrics such as total controls, graph leverage score, risk coverage rate, and policy coverage rate.

Governance object model:

- AI systems, models, datasets, products, agents/tools, risks, controls, policies, lifecycle stages, classifications, evidence, review tasks, and graph-linked relationships.

Automation approach:

- Risk/control inheritance through linked entities.
- AI Act classification workflow.
- Lifecycle approval automation.
- Evidence store with AI-based recommendations.

Maturity signals:

- Very strong public docs for workflow automation and governance graph mechanics.
- Good model for how Norinth should make derivation explainable, not mysterious.

Norinth implications:

- Norinth should expose why a risk/control/owner/review task exists: source event, linked object, rule, and inherited relationship.
- Control coverage and risk coverage need portfolio metrics, not just raw control assessment rows.

Sources:

- [Saidot automate governance workflows](https://help.saidot.ai/knowledge-base/automate-governance-workflows)
- [Saidot control catalogue](https://help.saidot.ai/knowledge-base/using-control-catalogue)
- [Saidot risk management](https://help.saidot.ai/knowledge-base/how-to-manage-risks)

### Fiddler AI

Primary positioning: AI observability and security platform for ML, LLM applications, and agents.

Observed workflow and UI surfaces:

- Fiddler agentic observability uses Projects -> Applications instead of the legacy Projects -> Models structure.
- Pre-built dashboards include Agent Performance Overview, Workflow Execution Traces, Tool Usage Analytics, and Error and Exception Tracking.
- Trace visualization shows agent steps, LLM calls, tool invocations, timing information, and parent-child relationships.
- Custom dashboards support KPI combinations, filters by agent type, user segment, and time period, shared dashboards, and alerts.
- Dashboard docs describe drift, traffic, data integrity, performance, flexible filters, date range, time zone, bin size, zoom, line/bar toggles, model comparisons, saved dashboards, and automatically generated monitoring dashboards.

Governance object model:

- Projects, applications, models, agents, traces, spans, LLM calls, tools, metrics, dashboards, alerts, guardrails, teams, users, and roles.

Automation approach:

- OpenTelemetry trace ingestion.
- LangGraph and Strands SDKs with automatic instrumentation.
- Guardrails for safety, faithfulness, and PII.

Maturity signals:

- Strongest reference for runtime/agent observability UI.
- It is governance-adjacent rather than a full compliance workflow platform, but its trace UX is directly relevant.

Norinth implications:

- Norinth's `agent.run` evidence should evolve into hierarchical trace views with per-step timing, model calls, tools, retrievals, guardrails, evals, and errors.
- Framework auto-instrumentation should target LangChain/LangGraph, OpenTelemetry, vector DBs, and tool/MCP frameworks.

Sources:

- [Fiddler agentic observability](https://docs.fiddler.ai/observability/agentic-monitoring)
- [Fiddler dashboards](https://docs.fiddler.ai/observability/dashboards.md)
- [Fiddler guardrails](https://docs.fiddler.ai/protect-and-guardrails/guardrails)

### Arize AX

Primary positioning: AI engineering platform for tracing, evals, experiments, prompt management, online evaluation, and observability.

Observed workflow and UI surfaces:

- Online eval docs show task creation from UI, project pages, evaluator pages, or spans.
- Task creation includes name, data source, evaluator selection from Eval Hub, column mappings, granularity, cadence, sampling rate, filters, and task logs.
- Results attach automatically to spans in tracing views.
- Running Eval Tasks show target, evaluators, recent run snapshots, logs, and links back to evaluated traces.
- Product docs include prompt hub, prompt playground, annotation queues, experiments, datasets, trace/session/span evals, and AI-assisted workflow automation.

Governance object model:

- Projects, traces, spans, sessions, evaluators, tasks, eval results, datasets, experiments, prompts, annotations, labels, filters, and logs.

Automation approach:

- Continuous production eval tasks.
- Historical backfills.
- LLM-as-judge and code evaluators.
- CI/CD experiment gates.

Maturity signals:

- Strongest reference for evaluation workflow design.
- It is an engineering/evals platform, not a complete governance product, but it solves a critical evidence layer.

Norinth implications:

- Norinth evals need managed evaluators and eval tasks, not only `eval.result` rows.
- Deployment gates should link to named eval suites, task runs, sample rate, filter scope, and failure taxonomy.

Sources:

- [Arize online evals on traces](https://arize.com/docs/ax/evaluate/online-evals/setting-up-online-evals)
- [Arize experiments](https://docs.arize.com/docs/ax/develop/datasets-and-experiments/run-experiments)
- [Arize prompt hub](https://docs.arize.com/docs/ax/develop/prompt-hub)

### Giskard

Primary positioning: LLM agent evaluation, red teaming, vulnerability scanning, and test management.

Observed workflow and UI surfaces:

- Giskard Hub documents a UI workflow: set up projects, agents, and knowledge bases; launch vulnerability scans; create test cases and datasets; review and refine test cases and metrics; run, review, schedule, and compare evaluation runs.
- Dashboard shows project overview counts for agents, datasets, evaluations, and knowledge bases, performance over time, recent evaluations, and recent datasets.
- Agent setup captures name, description, supported languages, API endpoint, headers, and request/response shape.
- Knowledge base setup supports uploaded JSON/JSONL with text and topics.
- Scan review shows security grades A-D, vulnerability categories, exact prompts used in attacks, agent responses, whether the attack succeeded, false-positive marking, conversion to test cases, and task creation.
- SDK docs show scans, tags for threat categories, knowledge-base-grounded scans, probe attempts, review status, dataset/test-case creation, and CI/CD gates.

Governance object model:

- Projects, agents, knowledge bases, scans, probes, attempts, datasets, test cases, checks, tasks, grades, evaluations, and review statuses.

Automation approach:

- Automated adversarial scans across OWASP LLM Top 10 and other threat categories.
- Promotion of successful attacks to regression tests.
- CI/CD failure gates based on security grade.

Maturity signals:

- Very concrete workflow docs and review actions.
- Strong example of turning runtime/test findings into durable remediation work.

Norinth implications:

- Norinth should implement vulnerability/test finding objects linked to traces, evals, incidents, and deployment gates.
- Findings should support false positive, convert to regression test, assign task, and close with rationale.

Sources:

- [Giskard Hub UI](https://docs-hub.giskard.ai/hub/ui/index.html)
- [Giskard scan review](https://docs.giskard.ai/hub/ui/scan/review-scan-results)
- [Giskard scan SDK](https://docs.giskard.ai/hub/sdk/guides/scans)

### Arthur AI

Primary positioning: GenAI monitoring, guardrails, metrics, and observability.

Observed workflow and UI surfaces:

- Quickstart guides users through project onboarding, selecting a Generative AI Agent or Chatbot, installing Arthur Engine, creating a model, selecting prompt injection as a metric, opening Chat Playground, and reviewing detections in Inference Deep Dive.
- Metrics docs describe numeric and sketch metrics, 5-minute cadence aggregation, metric versions, SQL query interfaces, custom metrics, dashboards, and alerting.
- Guardrail examples include prompt injection, hallucination, PII redaction, toxicity, sensitive data, keyword, and regex detection.

Governance object model:

- Projects, engines, models, metrics, metric versions, inferences, guardrail detections, dashboards, alerts, users, and projects.

Automation approach:

- Local or cloud Arthur Engine.
- Guardrail detectors and metric pipelines.
- Custom SQL metrics reusable across projects/models.

Maturity signals:

- Strong monitoring and guardrail mechanics.
- Governance workflow depth is lighter publicly than registry/risk/compliance platforms.

Norinth implications:

- Norinth should treat guardrails as versioned detectors with thresholds, not only logged decisions.
- Inference deep dive should become a core UI for model calls and guardrail/eval outcomes.

Sources:

- [Arthur platform quickstart](https://docs.arthur.ai/docs)
- [Arthur metrics querying](https://docs.arthur.ai/docs/metrics-querying-overview-1)
- [Arthur custom metrics](https://docs.arthur.ai/docs/custom-metrics)

## Cross-Platform Workflow Patterns

### 1. Inventory Is The Entry Point, Not The Dashboard

Mature platforms start with an inventory or registry: AI systems, use cases, models, agents, vendors, datasets, prompts, tools, and deployments. Dashboards summarize; they do not substitute for object management.

Norinth implication: the platform should prioritize object pages for applications, workflows, models, prompts, deployments, incidents, controls, risks, and reviews. The dashboard should be an executive and triage surface layered on top.

### 2. Workflow State Is Explicit

Credo has stages and steps. ModelOp has a six-step lifecycle. Saidot has lifecycle approvals. ValidMind has model stages, workflow steps, and workflow history. OneTrust uses intake, approval, attestation, signoff, and re-review.

Norinth implication: review tasks and deployment gates should become stateful workflows with transitions, prerequisites, assignees, approvers, due dates, exceptions, and audit logs.

### 3. Evidence Must Be Provenance-Aware

The credible products distinguish evidence source and reuse: runtime telemetry, test results, uploaded artifacts, policy mappings, human decisions, attestations, and external integrations.

Norinth implication: current control assessments should be backed by an evidence object model with `source_type`, `source_ref`, `collected_at`, `freshness`, `control_refs`, `review_status`, `accepted_by`, and `rejection_reason`.

### 4. Risk Is A Workflow, Not A Number

Risk appears as classification, assessment, inherited risk, residual risk, reviewer disposition, mitigation, exception, incident linkage, and re-review. Mature platforms make risk explainable.

Norinth implication: deterministic risk findings are a useful start, but the next layer should add risk assessment records, inherent/residual fields, controls applied, owner response, mitigation plan, exception linkage, and lifecycle transitions.

### 5. Agent Governance Requires Trace UX

Credo, Fiddler, Arize, Giskard, Holistic AI, and OneTrust all push toward agent-specific governance. The common UI need is traceability: agent steps, tools, model calls, retrieval, guardrails, evals, timing, and failures.

Norinth implication: `agent.run` should become a trace tree UI and normalized span model, not a single summary row.

### 6. Evaluations Are Managed Assets

Arize and Giskard show that evals need named evaluators, tasks, schedules, datasets, labels, filters, traces, and logs. Deployment gates should reference eval suites and run history.

Norinth implication: build `evaluation_suites`, `evaluation_tasks`, `evaluation_runs`, and `evaluation_findings` rather than expanding `eval.result` rows.

### 7. Governance Automation Must Be Explainable

Saidot is the strongest pattern here: inherited risks, controls, AI Act classification, and lifecycle approvals expose why something happened and how it was derived.

Norinth implication: every derived owner, risk, missing control, review task, deployment gate, and incident link should expose derivation details in the UI and API.

## UI/UX Patterns Norinth Should Emulate

- Left navigation organized by work: Inventory, Reviews, Risk, Controls, Evidence, Deployments, Monitoring, Incidents, Reports, Settings.
- Portfolio dashboard with filters by tenant, business unit, owner, lifecycle stage, risk tier, framework, provider, model, and date.
- Inventory tables with configurable columns, saved views, compound filters, chips, sorting, search, and bulk actions.
- Object detail pages with Overview, Activity, Risk, Controls, Evidence, Deployments, Monitoring, Incidents, Decisions, and Settings tabs.
- Review queue with assigned user/role, due date, SLA, escalation state, blocking dependency, and decision buttons.
- Deployment gate page showing required evidence, current evidence, missing controls, eval readiness, prompt version, approvals, exceptions, and release decision.
- Trace detail page showing nested spans, provider/model calls, prompts/hashes, retrieval docs, tools, guardrails, evals, token usage, latency, and errors.
- Evidence store with provenance, source object, control mapping, freshness, reviewer status, and audit history.
- Incident page with severity, impacted app/workflow/deployment, linked traces, linked risks/controls, owner, timeline, decisions, and closure rationale.
- Configuration pages for controls, risk rules, owner policies, roles, review queues, eval suites, and integrations.

## UI/UX Patterns Norinth Should Avoid

- A single all-purpose dashboard as the main product surface.
- Persona tabs or role dropdowns that pretend to be RBAC.
- Hardcoded framework coverage maps without source controls, evidence, or policy mappings.
- Risk scores without derivation, owner, evidence, or review disposition.
- Eval pass/fail rows without evaluator definition, data source, sample rate, run logs, and trace links.
- Incident rows without timeline, owner, impacted assets, decisions, and closure evidence.
- Deployment approval buttons that do not show why approval is blocked or permitted.
- Monitoring charts that cannot drill into traces and evidence.

## Mapping To Current Norinth

Current strengths from the repo:

- The SDK has a fail-open, observe-only telemetry architecture.
- FastAPI and provider auto-instrumentation can create model/application inventory without provider-client refactors.
- Demo app Norinth calls are now isolated behind app-owned observability adapters.
- The platform persists raw events and normalized governance entities.
- The platform already has prompt releases, deployment gates, incidents, owner assignments, decisions, exceptions, control assessments, risk findings, review tasks, and role-protected mutations.

Most important gaps:

- No object-first product UI yet.
- No configurable inventory views or object detail pages.
- No evidence store abstraction separate from raw events/control assessments.
- No managed eval suites/tasks/runs/findings.
- No hierarchical trace/spans UI for agents.
- Risk workflow is not yet a full assessment/remediation workflow.
- Incident workflow lacks production lifecycle depth.
- Control library is configurable but not a full framework/policy-pack system.
- Identity is header-derived local auth, not production SSO/session management.
- No audit packet/report generation.

Recommended product sequence:

1. Build object-first UI foundations.
  - Application, workflow, model, prompt, deployment, incident, risk, control, and review detail pages.
  - Replace dashboard-only posture with portfolio plus drilldown navigation.
2. Create a real evidence store.
  - Persist evidence records with provenance and review status.
  - Link evidence to controls, risks, deployment gates, incidents, evals, prompts, and traces.
3. Upgrade review/risk workflows.
  - Add risk assessment records with inherent/residual risk, mitigation, exception, owner response, and reviewer decisions.
  - Add workflow state transitions and audit history.
4. Build eval governance.
  - Add eval suites, tasks, runs, findings, and deployment gate linkage.
  - Support failure taxonomy, trace filters, sample rates, and run logs.
5. Build agent trace UX.
  - Normalize agent steps/spans and render nested trace trees.
  - Link model calls, retrieval, tools, guardrails, evals, and incidents into the trace.
6. Build reporting/audit packets.
  - Generate framework-ready evidence packets from object state, decisions, evidence, and runtime telemetry.
7. Expand frictionless SDK coverage.
  - Add OpenTelemetry ingestion/export compatibility.
  - Add auto-instrumentation for LangChain/LangGraph, vector DB/RAG frameworks, tool/MCP frameworks, guardrail libraries, and eval frameworks.

## Feature Catalogue Implications

The current `AI_GOVERNANCE_FEATURE_CATALOG.md` is directionally accurate. The research suggests these status interpretations should remain conservative:

- AI registry/model registry/vendor registry can be `Complete` only for instrumented usage, not enterprise-wide shadow AI.
- Agent registry should stay `Partial` until agent cards, autonomy level, tools, permissions, ownership, and trace tree UX exist.
- Prompt/template registry is `Complete` for event-derived lineage but not for prompt experimentation, approvals, or managed prompt hub workflows.
- Deployment registry/gates are `Complete` for the local verified slice, but enterprise deployment governance remains `Partial` until formal approvals, attestations, CI/CD integration, and audit reports exist.
- Risk register should remain mostly `Partial` because mature platforms treat risk as assessment workflow plus mitigation and residual risk, not only findings.
- Compliance/framework mapping should remain `Partial` or `Not started` until framework packs, obligation mapping, and audit packet generation exist.
- Evals should move from event capture toward managed eval workflow in future status updates.

## Strategic Differentiation For Norinth

Norinth should not try to become a traditional GRC intake tool first. The best wedge is:

1. Frictionless runtime evidence from real engineering systems.
2. Automatic construction of governed entities from SDK telemetry.
3. Explainable evidence-to-control and evidence-to-risk mapping.
4. Workflow surfaces that governance teams can act on without forcing app teams to rewrite code.

The competitor landscape validates the need for registries, controls, workflows, and audit reports. Norinth's opportunity is to make those artifacts emerge from live AI application behavior instead of manual questionnaires alone.

## Source Index

- Credo AI: [Product](https://www.credo.ai/product), [Workflow SDK docs](https://docs.sdk.credo.ai/core-concepts/workflow), [Artifacts](https://www.credo.ai/solutions/artifacts)
- Holistic AI: [Governance platform](https://www.holisticai.com/ai-governance-platform), [Learn center](https://www.holisticai.com/learn), [Inventory](https://www.holisticai.com/ai-inventory)
- IBM watsonx.governance: [AI use cases](https://dataplatform.cloud.ibm.com/docs/content/wsj/analyze-data/xgov-use-cases.html?context=wx&locale=en), [Governing AI assets](https://www.ibm.com/docs/en/watsonx/w-and-w/2.0.0?topic=governing-ai-assets), [RCM](https://dataplatform.cloud.ibm.com/docs/content/svc-watsonxgov/wxgov_rcm_desc.html?context=wx)
- OneTrust: [AI Governance](https://www.onetrust.com/content/onetrust/us/en/solutions/ai-governance), [Demo page](https://www.onetrust.com/resources/onetrust-ai-governance-demo-video/), [Announcement](https://onetrust.com/news/onetrust-introduces-ai-governance-solution)
- ModelOp: [Product](https://www.modelop.com/product), [Example workflows](https://modelopdocs.atlassian.net/wiki/spaces/dv33/pages/2115960853/Example+Governance+Workflows), [Controls](https://www.modelop.com/ai-governance-software/controls)
- Monitaur: [Platform](https://www.monitaur.ai/platform), [AI governance](https://monitaur.ai/ai-governance), [Vendor governance](https://info.monitaur.ai/monitaur-vendor-governance)
- ValidMind: [Inventory](https://docs.validmind.ai/guide/model-inventory/working-with-model-inventory.html), [Validation](https://docs.validmind.ai/guide/model-validation/managing-model-validation.html), [Oversight](https://docs.validmind.ai/training/administrator-fundamentals/organizational-oversight-reporting.html)
- Saidot: [Automations](https://help.saidot.ai/knowledge-base/automate-governance-workflows), [Control catalogue](https://help.saidot.ai/knowledge-base/using-control-catalogue), [Risk management](https://help.saidot.ai/knowledge-base/how-to-manage-risks)
- Fiddler: [Agentic observability](https://docs.fiddler.ai/observability/agentic-monitoring), [Dashboards](https://docs.fiddler.ai/observability/dashboards.md), [Guardrails](https://docs.fiddler.ai/protect-and-guardrails/guardrails)
- Arize: [Online evals](https://arize.com/docs/ax/evaluate/online-evals/setting-up-online-evals), [Experiments](https://docs.arize.com/docs/ax/develop/datasets-and-experiments/run-experiments), [Prompt hub](https://docs.arize.com/docs/ax/develop/prompt-hub)
- Giskard: [Hub UI](https://docs-hub.giskard.ai/hub/ui/index.html), [Scan review](https://docs.giskard.ai/hub/ui/scan/review-scan-results), [Scan SDK](https://docs.giskard.ai/hub/sdk/guides/scans)
- Arthur AI: [Platform quickstart](https://docs.arthur.ai/docs), [Metrics querying](https://docs.arthur.ai/docs/metrics-querying-overview-1), [Custom metrics](https://docs.arthur.ai/docs/custom-metrics)

