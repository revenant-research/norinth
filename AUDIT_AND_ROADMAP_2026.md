# Norinth — Platform Audit & Maturity Roadmap

**Date:** 2026-08-22 · **Scope:** entire repository (`packages/python-sdk`, `apps/platform`, `demo-apps`, `scripts`, frontend, ops) · **Method:** full source read of ~10k Python + ~3k TS LOC, five parallel specialist audits (storage, API/authz, SDK, frontend/ops, regulatory research), and **live black-box reproduction** of the worst findings against a running instance.

> This document is the working record. The highest-severity items marked **[reproduced]** were confirmed live, not inferred from code.

---

## 1. Verdict

Norinth is a **well-conceived, honestly-scoped prototype** with a genuinely good core idea: turn runtime telemetry into governance evidence with a fail-open SDK, an open/closed licensing seam, and a control-mapping engine. The architecture's *intent* (SDK captures evidence, platform derives posture, protocol is the only coupling) is sound and the founder's own docs (`AI_GOVERNANCE_FEATURE_CATALOG.md`) are refreshingly candid about what is and isn't real.

**But as shipped it is not deployable to a Fortune-500 or a health system, and its central promise — trustworthy governance evidence — is currently falsifiable by anyone who can reach the ingestion endpoint.** The platform computes a customer's entire compliance posture, deployment approvals, and risk register from **unauthenticated, client-authored events with a hardcoded key and no tenant binding**. A governance product whose evidence can be forged is worse than no product, because it manufactures false assurance.

The gap between "verifiable demo" and "mature platform" is large but tractable. The code is small, readable, and mostly correct in the happy path; the failures are architectural (trust model, tenancy, persistence engine, evidence integrity) rather than a thousand small bugs. That is fixable — and this document lays out how.

**Bottom line:** ~6–9 months of focused work to reach a credible SOC 2 Type II / ISO 42001-aligned enterprise MVP; the security and evidence-integrity items in §3 are prerequisites to *any* external pilot.

---

## 2. What was audited & confirmed live

| Area | Method | Result |
|---|---|---|
| Ingestion trust model | Live `curl` | **Confirmed:** injected governance evidence + a forged *passing* eval into a tenant that was never provisioned, using the default `Bearer dev` key. |
| Separation of duties | Live | **Confirmed:** an `org_admin` self-assigned `governance_admin`, gaining `gate.decide`, `risk.accept`, `incident.close`, `review.decide`. |
| `must_change_password` | Live | **Confirmed:** UI-only; the seeded default admin performed privileged actions while still flagged. |
| Ingestion robustness | Live | **Confirmed:** a `prompt.event` missing `artifact_ref` crashes ingestion with HTTP 500 (`prompts.py:100`); raw events were already written before the pipeline aborted (no transaction). |
| DB engine | Live PRAGMA | **Confirmed:** SQLite `journal_mode=delete` (not WAL). |
| Docker/ops | Static | **Confirmed:** image never builds/copies the React bundle; `docker-compose` sets `NORINTH_DB_PATH` while code reads `NORINTH_PLATFORM_DB`; `Dockerfile:11` `COPY requirements.txt` fails (file is at `apps/platform/requirements.txt`). |
| Not a git repo | Static | **Confirmed:** no `.git` anywhere — no history, no CI, no review gate. |

---

## 3. Critical findings (showstoppers — must fix before any pilot)

Severity legend: **C**ritical / **H**igh / **M**edium / **L**ow. Each item is deduplicated across the five audits; `file:line` references are exact.

### C-1 · Ingestion is effectively unauthenticated and tenant-spoofable **[reproduced]**
`dependencies.py:37-40` gates ingestion on a single hardcoded string `Authorization: Bearer dev`. The tenant of every event is whatever the client puts in `attributes.metadata.tenant_id` (`raw_events.py:107`) — there is no binding between the authenticated principal and the tenant. Optional HMAC (`ingestion/routes.py:25-36`) is off unless `NORINTH_SIGNING_SECRET` is set, and even when on it is a single shared symmetric secret with no key id, timestamp, or nonce → replayable, and any holder forges evidence for any tenant.
**Impact:** Anyone who can reach `/v1/events/batch` can fabricate or poison any organization's AI inventory, risk findings, control evidence, incidents, and deployment approvals. This is the root cause that makes the entire evidence base untrustworthy.
**Fix:** per-tenant API keys (hashed at rest, rotatable, scoped); derive `tenant_id` *from the key*, never from the payload; reject events whose payload tenant ≠ key tenant; make HMAC mandatory with key-id + timestamp + nonce and a replay window; add an ingestion allow-list of event `schema_version`s.

### C-2 · Governance posture & deployment gates are computed from client-authored events → gates auto-approve on forged evidence
Two independent mechanisms approve deployments with **no human and no real evidence**:
- `deployments.py:189-201`: when nothing is "required" (no open risks, missing controls, or material changes; a linked prompt; ≥1 passing eval) the gate is written directly as `approved` with `actor_ref=NULL, rationale=NULL, decided_at=NULL`.
- `count_passing_eval_evidence` (`deployments.py:299-322`) trusts `attributes.passed is True` from a client `eval.result`. Emit `deployment.event` + matching `prompt.event` + a fake `eval.result{passed:true}` and the gate approves itself.
- `apply_decision_status` (`workflow.py:702-724`, reachable via `POST /api/decisions` with `target_type=deployment_gate`) sets `gate_status='approved'` with **no evidence check at all**, bypassing the guard in `set_deployment_gate_status` (`deployments.py:341-348`). *(Agent-confirmed via code; my live repro was blocked by the C-6 crash, but the path is unambiguous.)*
**Impact:** The single most important control in the product — "you cannot ship without evidence" — is defeated by the same SDK key from C-1, or by any `gate.decide` holder via the decisions route.
**Fix:** evidence must be first-party and attestable (signed by a trusted CI identity, not a self-reported boolean); gates must default to **blocked, never auto-approved**; every approval must have a non-null human actor + rationale + timestamp; route all gate transitions through one guarded function; enforce that eval evidence originates from a registered eval runner, not arbitrary ingestion.

### C-3 · Cross-tenant blast radius: global config tables are writable by any org admin
`control_library`, `risk_rules`, `review_queue_policies`, `owner_assignment_policies`, `permissions`, `role_permissions` have **no `tenant_id`** (`governance_policy.py:145-167`, `workflow.py:80-104`) yet are written through tenant-scoped `config.write` routes (`api/routes.py:217-295`). `require_config_write(actor)` authorizes against the actor's own tenant, but the row lands in a platform-global table consumed by `refresh_governance_assessments`/`refresh_workflow_state` for **every** tenant.
**Impact:** Tenant A's org_admin can `POST /api/control-catalog` to blank a control's `required_fields` (flipping every other tenant's assessment to "passing"), or reroute every tenant's review queue. One customer silently rewrites all customers' compliance posture.
**Fix:** make these tables tenant-scoped (add `tenant_id`, include it in the PK), or gate global edits behind `require_super_admin`; seed per-tenant copies at org creation.

### C-4 · Separation of duties is broken — `org_admin` self-escalates to full governance authority **[reproduced]**
`org_admin` holds `role.assign` and can grant `governance_admin` (carrying `gate.decide`, `risk.accept`, `incident.close`, `review.decide`) to itself via `POST /api/org/role-assignments`. Compounding it: the assignee-self-approval shortcut (`authorization.py:108-115`) lets whoever the queue auto-assigned a task act on it with no permission grant, and maker-checker (`api/routes.py:91-104`) is a no-op because most decision targets (gates, findings) carry no `submitted_by`/`created_by`.
**Impact:** One person can provision themselves, assign themselves the reviewer role, become the auto-assignee, and approve their own deployment gates and accept their own risks — with no second party. This nullifies the core value proposition for regulated buyers (SoD is table-stakes for SOC 2 / EU AI Act Art 14 / 21 CFR Part 11).
**Fix:** administration and governance-decisioning must be distinct permission planes; forbid self-assignment of decision roles; enforce true maker-checker with stored maker identity on every decidable object; add a configurable N-eyes policy.

### C-5 · Every ingest triggers a platform-wide full recompute — O(all data) per batch
`ingestion/routes.py:43-46` synchronously runs `refresh_lifecycle_state` + `refresh_governance_assessments` + `refresh_workflow_state` + `refresh_deployment_gates`, each of which `SELECT DISTINCT ... FROM governance_applications` across **all tenants** and re-reads/JSON-decodes every application's **entire event history** and every deployment version (`lifecycle.py:91-101`, `governance_policy.py:254-265`, `deployments.py:182-186`). Aggregate ≈ **O(TotalEvents × Applications × Rules)** per single-event batch, on a single-writer SQLite connection with `journal_mode=delete` and no WAL (`raw_events.py:16-21`).
**Impact:** Ingest latency grows unbounded with historical volume; the write lock is held during the recompute so concurrent ingests/reads hit `database is locked`. A tenant with 200 apps × 10k events re-processes ~2M evaluations to record one span. This is both a hard scaling wall and a trivial DoS (amplified by C-1).
**Fix:** move to Postgres; make derivation **incremental** (process only new events, keyed off a watermark) and **async** (queue/worker, not inline with the HTTP request); scope every recompute to the affected `(tenant, app)`; add the missing composite indexes (`raw_events.py:58-62`, `governance_observed_events.entity_type`).

### C-6 · Human decisions are silently erased on every ingest; ingestion is not transactional or robust **[reproduced]**
- `assess_controls`/`upsert_rule_finding` use `INSERT OR REPLACE` on a deterministic key (`governance_policy.py:336-361, 438-462`). When a reviewer sets a risk finding to `accepted` or a control to `waived`, the **next ingest recomputes the same id and resets status to `open`/`missing`** — accepted risks silently reopen, waivers vanish, and the reopened risk can flip a gate that was already auto-approved (interacts with C-2). *(Storage audit; mechanism is unambiguous.)*
- The pipeline runs `insert_events` → 6 processors in **separate connections with no enclosing transaction** (`ingestion/routes.py:38-46`). A crash mid-pipeline leaves `sdk_events` populated while derived state reflects the pre-batch world, with no rollback and no idempotency key (`sdk_events` has no unique `(trace_id, span_id)`), so retries double-count.
- **[reproduced]** A well-formed event missing an optional attribute (`prompt.event` without `artifact_ref`) throws `KeyError` → HTTP 500 (`prompts.py:100`). The platform validates only the event *envelope* (`schemas/events.py`), never `attributes`, so malformed-but-plausible events crash ingestion after partial writes.
**Fix:** derived governance state must be layered *over* immutable human decisions, never overwrite them (separate `system_status` from `decision_status`, or event-source the decisions); wrap the whole pipeline in one transaction with an idempotency key on the batch; validate `attributes` per event type server-side and return 4xx (never 5xx) for bad payloads; add `UNIQUE(trace_id, span_id)`.

### C-7 · `POST /api/users` lets any tenant's `config.write` holder overwrite any account, including the super admin (lockout DoS)
`api/routes.py:259-266` → `upsert_platform_user` does `ON CONFLICT(user_ref) DO UPDATE status`; the payload carries no `tenant_id` so `require_permission` back-fills the actor's own tenant and passes. `POST /api/users {"user_ref":"admin@norinth.local","status":"suspended"}` disables the super admin; `count_super_admins()` still returns 1 so re-seed never fires → **permanent platform lockout**. Same primitive suspends/re-enables any tenant's users cross-tenant.
**Fix:** remove this route or scope writes strictly to `actor.tenant_id` with a tenant-match check on the *existing* row; never allow cross-plane user mutation; protect the last super admin.

### C-8 · SDK: one bad event permanently kills all telemetry while reporting healthy **[reproduced by SDK auditor]**
`transport.py:76`: `json.dumps` runs *outside* the `try` in the worker loop (`_run`, `:70-73`), which has no exception handling. A single non-JSON-serializable value (reachable via `agent_run(steps=[...])` verbatim, a `NaN` score, or `usage.__dict__` fallback) raises, the daemon thread dies and is never restarted, all subsequent events queue to 1000 then drop forever — while `stats` reports `dropped=0, failed_sends=0`. This is the worst possible failure for a governance recorder: it stops silently and lies about it.
**Fix:** wrap the entire worker loop body in try/except; serialize defensively (`default=str`, `allow_nan=False`); add a supervisor that restarts a dead thread; surface real health (queue depth, thread-alive, last-success timestamp) and never fabricate zeros.

---

## 4. High-severity findings

### Tenancy & authorization
- **H-1 · NULL-tenant fail-open.** `require_actor_scope` skips a field whenever either side is falsy (`authorization.py:54-59`); ingested rows frequently have `tenant_id=NULL`; `role_scope_matches` treats a NULL assignment scope as matching *every* tenant (`:62-68`). A governance_admin can act on any NULL-tenant object cross-tenant, and `POST /api/role-assignments {tenant_id:null}` grants a **global** role. Fail closed on NULL; make `tenant_id NOT NULL`.
- **H-2 · `entity_id` collisions across tenants.** `entity_id(...)` renders `None` tenant as empty string (`entities.py:10-12`); two tenants that omit tenant and share `(project, environment, application_name)` get the **same PK** and their counters merge (`entities.py:224`). Also `list_application_events` folds **all tenants' `sdk.health`** into every tenant's control evidence (`governance_policy.py:298-306`).
- **H-3 · `/api/sdk-health` drops the tenant filter** (`api/routes.py:471-473`) → any authenticated user reads every tenant's telemetry sharing a project/env name.
- **H-4 · `/api/network/vendors` cross-tenant AIBOM** (`compliance.py:135-160`) keyed only on role-name membership; combined with H-1 a self-granted global role dumps other orgs' model inventories.
- **H-5 · Guessable object ids enable IDOR.** Deterministic unsalted SHA-256 over low-entropy names (`entities.py:10-12`); decision/exception routes fetch by id with no tenant predicate and rely on the (NULL-defeated) scope check.

### Session, auth, web security
- **H-6 · No brute-force protection or lockout on login** (`api/auth.py:52-56`); 409 "already exists" is a user-enumeration oracle; `platform_users.email` has an index but **no UNIQUE constraint** (`workflow.py:26,179`) → two users can share an email.
- **H-7 · Session cookie lacks `Secure`** (`api/auth.py:27-35`); opaque tokens stored **plaintext as the PK** (`workflow.py:38-45`), never rotate, and survive password change/reset. Store hashed; add `Secure`; rotate on privilege change; revoke all sessions on password change.
- **H-8 · No CSRF defense-in-depth.** Cookie auth + `credentials:"include"` with `samesite=lax` as the *only* protection and no token/Origin check (`main.py`, `api.ts:152-158`).

### Data integrity, audit, retention
- **H-9 · Audit log is not tamper-evident** (`audit.py:13-24`): plain autoincrement table, no hash chain, no signature; anyone with DB access can rewrite/delete rows. It is also written in a **separate transaction after** the mutation (`api/routes.py:387-391`) → mutations without audit rows on crash. Hash-chain it (WORM), write it in the same transaction, export to an append-only sink.
- **H-10 · No retention, purge, or right-to-erasure anywhere** (whole storage layer): the only `DELETE`s are for sessions. `sdk_events` holds `user_id`/PII and hashes indefinitely; suspending an org leaves all its data. Blocks GDPR/EU-AI-Act/HIPAA compliance and tenant offboarding.
- **H-11 · Lost updates on JSON set-columns.** `fetch_one`+`merge_sets`+`INSERT…ON CONFLICT DO UPDATE SET providers=excluded.providers` (`entities.py:225-233` etc.) is a read-modify-write in Python; concurrent batches clobber each other → a provider/model silently drops from inventory.

### SDK privacy & correctness (the "metadata + hashes, not content" claim is violated)
- **H-12 · Unsalted `sha256(repr(value))`** (`privacy.py:15-17`) is dictionary-reversible for low-entropy inputs, globally linkable across tenants, and unstable for non-literals (memory addresses in `repr`). Key the hash with the signing secret + a per-tenant salt.
- **H-13 · Raw content leaves the process by default**, ungated by `capture_content`: exception messages (`client.py:101`, provider 400s echo inputs, customer `ValueError(f"...{ssn}")`), `agent.run` steps/outcome verbatim (`client.py:340-342`), incident `title` (`client.py:479`), `guardrail.matched_rules`, URL path segments as `name` (`autoinstrument.py:167-171`), and `user_id`/`tenant_id`/`use_case` scraped from arbitrary request bodies (`privacy.py:53-61`) with no length cap. For the HIPAA-adjacent claims demo this ships identifiers by default. `NORINTH_CAPTURE_CONTENT=true` flips global raw capture and is **not** reported in `sdk.health`.
- **H-14 · Auto-instrumentation misses most real traffic** → negative assurance. Only sync OpenAI **Responses** and sync Anthropic **`messages.create`** are patched. Missing: `chat.completions` (the dominant API), all **async** clients (`AsyncOpenAI`/`AsyncAnthropic` — the canonical FastAPI stack), Anthropic **streaming** (`.stream()` bypasses `create`), OpenAI `.parse()`/structured output, embeddings, system prompts, tools. An inventory that omits `chat.completions` and async is dangerously incomplete (`autoinstrument.py:20-49`).
- **H-15 · `@trace`/`wrap()` on async code record fabricated success before execution** (`client.py:79-131`) → the audit trail is fiction for async functions, and trace context resets before the coroutine runs, orphaning nested `model.call`s.
- **H-16 · Middleware buffers the entire request body with no size cap** (`autoinstrument.py:109-116`) and its `replay_receive` never yields (`:118-121`) → breaks streaming, can freeze the worker on SSE endpoints, double-buffers large uploads. Client body fields become governance truth (`:124-125`).
- **H-17 · HTTP status not observed; handled errors recorded as success** (`autoinstrument.py:129-153`) → error-rate dashboards are wrong (a 502 reads as `success`).
- **H-18 · At-most-once delivery sold as "attested evidence"** (`transport.py:92-99`): no retries/backoff/spool/idempotency; one 5xx discards the batch at `debug` level. No `event_id`, no SDK version, no cost/region/model-fingerprint in the schema (`schemas.py:19-34`). No fork handling → gunicorn/celery prefork workers have a dead transport (`transport.py:38-40`). No `atexit` flush → tail loss on every clean exit.

### Ops & supply chain
- **H-19 · Not a git repository.** No history, no CI, no PR review; the licensing/repo-split plan presupposes VCS that doesn't exist. `git init` + a real `.gitignore` (add `node_modules/`, `*.tsbuildinfo`, `*.db`, `*.sqlite3`) **before** the first commit; delete 18 stray verify DBs, `egg-info/`, `__pycache__`, the 0-byte `frontend/norinth-platform.db`.
- **H-20 · Docker is unbuildable / mis-wired.** `Dockerfile:11 COPY requirements.txt` fails (wrong path); compose sets `NORINTH_DB_PATH` but code reads `NORINTH_PLATFORM_DB`; no frontend build step (ships a hand-built bundle); runs as root; no healthcheck; SQLite-in-container = data loss on scale-out.
- **H-21 · Zero automated tests + one non-idempotent live script.** `verify_live.py` is the only test, dies on a second run against the same DB (fixed emails → 409), and the README claims it exercises a demo-app/gate-blocking pipeline it does not (`README.md:148-154`). No lint/type-check/CI/pre-commit.

---

## 5. Selected medium/low findings (representative, not exhaustive)
- **M · Free-form enums = state mass-assignment.** `DecisionRequest.decision` is any string; `apply_decision_status` writes unknown strings straight to `status` (`workflow.py:702-733`) → `decision:"totally_done"` escapes the review workflow. Same for user `status`, severity. Constrain every enum server-side.
- **M · `AuthorizationError`/`ValueError` → HTTP 500** on several routes (`api/routes.py:231-237,364,404`), leaking stack context and giving a crash-probing surface. Map to 400/403/404 uniformly.
- **M · Frontend audit-log filters are a no-op** — `useResource.reload` captures a stale closure (`admin.tsx:36-45`), and two `eslint-disable` comments hide the exact bug (for a linter that isn't installed).
- **M · SDK CLI scanner is unreliable** — flags any `.create()`/`model=` (matches boto3/ORM/stripe) yet misses the demos' real models; swallows parse failures while incrementing `total_files_scanned` (`cli.py:40-116`).
- **M · Migrations are `ALTER TABLE` in bare `except: pass`** (`workflow.py:25-35` etc.), no version table, cross-module schema ownership (`review_tasks` created in `lifecycle.py`, altered in `workflow.py`). Adopt Alembic.
- **M · Legacy `dashboard/html.py` is dead & broken** (405 lines, unreachable fallback, fetches authed API with no login). Delete. `apps/demo-ai-app` is an undocumented orphan 4th demo — delete or fold in.
- **L · No pagination/virtualization anywhere** (frontend + unbounded API lists); `list_events` silently caps governance computations at 10k/5k (`governance.py`, `compliance.py:29-32`) → undercounted posture with no signal.
- **L · Accessibility:** zero `aria-*` in `App.tsx`, 23 placeholder-only inputs, `Enter`=confirm even on Cancel, sub-AA contrast. No i18n, no dark mode, unusable < 700px.
- **L · Trace ids are proprietary, not W3C `traceparent`; no OpenTelemetry bridge** — Norinth traces cannot join the APM/OTel traces every enterprise already runs (see §6.6).

---

## 6. Feature & robustness gaps for a 2026 AIO governance platform

Grounded in the current (Aug 2026) regulatory and standards landscape. **Dates verified against primary sources this session.**

### 6.1 The single biggest 2026 correction the founder's docs miss
The **EU AI Act Digital Omnibus (Regulation (EU) 2026/1744)** is **enacted and in force since 27 July 2026**. It **deferred the high-risk regime**: standalone Annex III systems now apply from **2 December 2027** (was 2 Aug 2026), and product-embedded/medical-device AI (Annex I, incl. MDR/IVDR) from **2 August 2028** (was 2 Aug 2027), with **fixed dates and no standards-availability condition**. What is **live now (2 Aug 2026)**: Art 5 prohibitions (+ new CSAM/NCII ban, safeguards due 2 Dec 2026), Art 4 literacy, **GPAI Chapter V with Commission fining powers (up to 3%/€15M)**, and **Art 50 transparency** (chatbot disclosure, machine-readable AI-content marking; marking grace to 2 Dec 2026, watermark interoperability by 2 Feb 2027).
> **Product implication:** don't sell "high-risk is live." Sell the **~16-month runway to Dec 2027** as the reason to instrument now — logging (Art 12) with **≥6-month retention** (Arts 19/26(6)), Annex IV technical documentation, FRIA workflows (Art 27), and serious-incident timers (**15/10/2 days**, Art 73) map *directly* onto what Norinth already captures. Also note: **no CEN-CENELEC harmonised standard is cited in the OJ yet** (EN 18286 QMS closest, Q4 2026 target) — the standards vacuum is a wedge for evidence-automation tooling.

### 6.2 Framework coverage: from 9 hard-coded controls to real crosswalks
Today the control library is 9 seeded controls with framework *string labels* (`governance_policy.py:17-90`). A 2026 buyer expects living, mapped crosswalks:
- **NIST AI RMF 1.0** + **AI 600-1 Generative AI Profile** (the 12 GAI risk categories with action IDs) — the US baseline.
- **NIST SP 800-53 "Control Overlays for Securing AI Systems" (COSAIS)** — draft through 2026 (GenAI, predictive, single/multi-agent, secure dev overlays); track and pre-map.
- **ISO/IEC 42001:2023** Annex A (~38 controls) — **now table-stakes**, moving from differentiator to buyer prerequisite; add **ISO/IEC 42005** (AI impact assessment, 2025) and **ISO/IEC 23894** (risk).
- **EU AI Act** Art 9/10/11-AnnexIV/12/13/14/15/17/72/73 — as concrete evidence requirements, not labels.
- **SOC 2** (+ AICPA AI assurance) and **HITRUST AI** for the buyers' own audits.
- **Regulatory change tracking** as a product surface (the Omnibus is proof this list moves quarterly).

### 6.3 Healthcare / medical is a distinct, high-value product line — and needs its own module
- **FDA** finalized the **PCCP guidance** (predetermined change control plans, retitled to cover AI-DSF not just ML) and issued **draft Total Product Life Cycle lifecycle-management** guidance in 2025. A Norinth "PCCP evidence pack" (change logs, performance monitoring, retraining lineage) is a natural fit — this is exactly the material-change + deployment-gate data model, pointed at a regulated artifact.
- **Joint Commission + CHAI** launched the **Responsible Use of AI in Healthcare (RUAIH) voluntary certification on 1 June 2026**, with CHAI **model cards ("AI nutrition labels")** and quality-assurance-lab frameworks. Support producing/consuming CHAI model cards and mapping evidence to the RUAIH governance/monitoring criteria.
- **ONC HTI-1 DSI** transparency (the 31 source-attribute set for certified decision-support) — map retrieval/prompt lineage to source attributes.
- **HIPAA** (Security Rule NPRM), **BAA**, **42 CFR Part 2**, and state health-AI laws (CA **AB 3030** GenAI patient-communication disclosure, IL therapy-bot limits). **Prerequisite:** the SDK's default raw-content leakage (H-13) must be fixed before *any* PHI-adjacent deployment.
- **21 CFR Part 11 / GxP validation (IQ/OQ/PQ)** and electronic-signature semantics for regulated records — the audit log (H-9) must be WORM-grade first.

### 6.4 Agentic governance — the fastest-moving 2026 requirement
Norinth captures `agent.run` and `tool.call`, which is a head start, but agentic governance in 2026 means more:
- Map to the **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10: planning, tool use, identity, supply chain, code execution, memory, inter-agent comms, cascading failures, human-agent trust, rogue agents) and **MITRE ATLAS** agentic techniques.
- **Agent identity & authorization** (agent IDs, scoped credentials, tool allow-lists, human-in-the-loop checkpoints, kill switches) — governance of *what an agent may do*, not just what it did. Singapore's Model AI Governance Framework for Agentic AI is an emerging template.
- **Runtime enforcement (`enforce` mode)** — the SDK's roadmap already names this; it's what turns Norinth from a recorder into a control.

### 6.5 Security posture as a first-class governance dimension
- **OWASP Top 10 for LLM Applications 2025** and **Agentic 2026**, **NIST adversarial ML taxonomy (AI 100-2e2025)**, prompt-injection defenses, **MCP security** (tool poisoning, confused deputy).
- **Model & data supply chain:** the AIBOM should be true **CycloneDX 1.6+ ML-BOM / AI-BOM** with model provenance, **OpenSSF Model Signing / Sigstore** attestations, training-data summaries (EU GPAI template), and dataset lineage — not a hand-rolled JSON (`cli.py`).

### 6.6 Enterprise interoperability & the "system of record" bar
- **OpenTelemetry GenAI semantic conventions** (still "Development"/pre-stable in 2026, moved to a dedicated repo; `invoke_agent`/`execute_tool`/`chat` span tree) — adopt `gen_ai.*` and W3C `traceparent` so Norinth joins existing APM/SIEM, rather than inventing `trc_...` ids. Offer OTel/OpenInference ingestion *and* export.
- **LLM-gateway ingestion** (LiteLLM, Portkey, Kong AI Gateway, Cloudflare AI Gateway) — most enterprises will route through a gateway; meet them there instead of relying on per-SDK patching (which H-14 shows is fragile).
- **Shadow-AI discovery** — the top-ranked 2026 buyer capability; passive discovery of un-instrumented AI usage (network, gateway, CASB, code scan) to complement runtime telemetry.

### 6.7 Competitive table-stakes (Credo AI, Holistic AI, IBM watsonx.governance, OneTrust, Vanta/Drata AI, Microsoft Purview, Trustible, Saidot…)
Every serious 2026 platform ships, and RFPs will demand: **AI use-case intake/triage with risk tiering** (Norinth has a start via `/api/intake`), **policy-as-code**, **evidence automation & audit-packet/report generation**, **framework crosswalks**, **model registry & vendor/third-party AI risk**, **FRIA/impact-assessment templates**, **bias/fairness testing**, **explainability**, **data lineage**, **human-oversight workflow**, **continuous monitoring & drift**, **regulatory change tracking**, and **integrations/webhooks/Terraform**.

### 6.8 Enterprise/medical buyer infrastructure requirements (hard gates in procurement)
| Requirement | Status today | Needed |
|---|---|---|
| SSO **SAML/OIDC + SCIM** | ❌ password-only sessions | Table-stakes for any F500/health buyer |
| **RBAC/ABAC** with SoD | ⚠️ RBAC exists but self-escalatable (C-4) | Fix SoD; add ABAC/attribute scoping |
| **Immutable/WORM audit log** | ❌ (H-9) | Hash-chained, exportable to SIEM |
| **Encryption at rest / KMS / BYOK** | ❌ | Table-stakes; BYOK for health/finance |
| **Data residency / multi-region** | ❌ single SQLite | Region pinning; the schema has no region field |
| **Postgres + HA/DR, backups, SLA** | ❌ SQLite (C-5) | Prerequisite for any production tenant |
| **HIPAA BAA / SOC 2 Type II / HITRUST / FedRAMP** | ❌ | Sales-blocking without them |
| **Retention / legal hold / e-discovery** | ❌ (H-10) | Configurable retention + hold + export |
| **21 CFR Part 11 e-signatures (GxP)** | ❌ | For medical/pharma regulated records |
| **API-first + webhooks + Terraform provider** | ⚠️ REST read APIs only | Eventing, webhooks, IaC |
| **Observability/SIEM export** | ❌ | Splunk/Elastic/OTel export |

---

## 7. Remediation roadmap

Phased so that each phase is independently shippable and unblocks the next. Effort is rough (1 senior eng-month = 1u).

### Phase 0 — Stop the bleeding (2–3 weeks) — *prerequisite to any external eyes*
1. `git init`, real `.gitignore`, first clean commit; add CI (ruff + mypy + tsc + `verify_live.py` on a fresh DB). **[H-19, H-21]**
2. Fix ingestion trust: **per-tenant hashed API keys, tenant derived from key, mandatory HMAC with timestamp/nonce.** **[C-1]**
3. Enforce `must_change_password` and account status **server-side** in `current_actor`; rotate default creds; block the last-super-admin lockout. **[C-4, C-7]**
4. Gates default **blocked**; every approval requires a non-null human actor + rationale; route all transitions through one guarded function; remove the decisions-route bypass. **[C-2]**
5. Split administration from governance-decisioning permissions; forbid self-assignment; real maker-checker. **[C-4]**
6. Validate event `attributes` server-side; return 4xx not 5xx; wrap the ingest pipeline in one transaction; add `UNIQUE(trace_id, span_id)`. **[C-6]**
7. SDK: wrap the worker loop in try/except + supervisor; serialize defensively; report true health. **[C-8]**
8. Fix Docker (`COPY` path, env var, add non-root + healthcheck + frontend build) so `docker compose up` works. **[H-20]**

### Phase 1 — Trustworthy multi-tenant core (6–8 weeks)
9. **Migrate to Postgres**; connection pooling; Alembic migrations; `tenant_id NOT NULL` everywhere; fail-closed authorization on NULL. **[C-5, H-1, M-migrations]**
10. **Incremental + async derivation** (event → queue → worker, watermark-scoped to `(tenant, app)`); add missing indexes. **[C-5]**
11. Tenant-scope the global config tables (or gate on super-admin); per-tenant seeding. **[C-3]**
12. Layer derived state over immutable human decisions (never overwrite). **[C-6]**
13. **WORM, hash-chained audit log** written in-transaction with each mutation; SIEM export. **[H-9]**
14. Session hardening: hashed tokens, `Secure`, rotation, revoke-on-change, login rate-limit/lockout, CSRF tokens, unique email. **[H-6, H-7, H-8]**
15. Retention + right-to-erasure + tenant offboarding delete. **[H-10]**
16. Encryption at rest + KMS; secrets management.

### Phase 2 — Trustworthy evidence & SDK (6–8 weeks)
17. SDK privacy overhaul: keyed/salted hashing, gate *all* free-text (agent steps, exception messages, titles, matched rules) behind `capture_content`, cap lengths, report `capture_content` in health, strip request-body PII by default. **[H-12, H-13]**
18. Auto-instrumentation: cover `chat.completions`, async clients, Anthropic streaming, structured output; capture system prompts/tools/status; fix async `@trace`; fork/atexit handling; retries + disk spool + idempotency + `event_id` + SDK version + cost/region/model-fingerprint. **[H-14–H-18]**
19. **OpenTelemetry GenAI conventions + W3C traceparent**; ingest OTel/OpenInference and LLM-gateway telemetry (LiteLLM/Portkey/Kong); export OTel. **[§6.6]**
20. Signed/attested evidence for gate-blocking (CI identity, not self-reported booleans). **[C-2 hardening]**

### Phase 3 — Enterprise readiness (8–10 weeks)
21. **SSO: SAML/OIDC + SCIM**; ABAC. Real RBAC admin UI.
22. Framework crosswalk engine (NIST AI RMF + GenAI Profile, ISO 42001 Annex A + 42005, EU AI Act Art 9–17/72/73, SOC 2) with evidence mapping and gap views. **[§6.2]**
23. **Audit-packet / report generation**, FRIA/impact-assessment templates, policy-as-code, regulatory change tracking. **[§6.7]**
24. Webhooks/eventing, Terraform provider, SIEM export; pagination/virtualization; frontend refactor (router + data layer), a11y, i18n. **[L-items]**
25. HA/DR, backups, multi-region/data-residency; begin SOC 2 Type II.

### Phase 4 — Regulated verticals & agentic (ongoing)
26. **Healthcare module:** CHAI model cards + RUAIH mapping, FDA PCCP/lifecycle evidence packs, ONC HTI-1 DSI source attributes, 21 CFR Part 11 e-signatures, HIPAA BAA + HITRUST. **[§6.3]**
27. **Agentic governance:** OWASP Agentic 2026 + ATLAS mapping, agent identity/tool-allowlists/HITL checkpoints/kill switches, and the opt-in **`enforce` mode** to move from recorder to control. **[§6.4, 6.5]**
28. Shadow-AI discovery; true CycloneDX AI-BOM + model signing (Sigstore/OpenSSF). **[§6.5, 6.6]**

---

## 8. What to keep (this is not a teardown)
- The **fail-open, observe-by-default SDK philosophy** and the **open-client/closed-platform seam** are the right strategic bets.
- The **event → entity → control/risk → review/gate/incident** derivation model is a sound spine; it needs to be incremental, tenant-safe, and decision-preserving, not rebuilt.
- The **intake → risk-tier → routed-review** flow and the **material-change fingerprinting** idea are genuinely differentiated primitives (fix the removal-blindness in `lifecycle.py:150-169` and the recompute cost).
- The **founder's honesty** in the feature catalog is an asset — the roadmap above is mostly making the docs' own "App-owned / not-started" columns real, in a security-and-tenancy-safe way.

*Sources for §6 regulatory claims: EU AI Act primary text (artificialintelligenceact.eu), Regulation (EU) 2026/1744 (EUR-Lex ELI reg/2026/1744), Gibson Dunn / FPF / Orrick omnibus analyses; NIST CSRC COSAIS; OWASP GenAI Security Project (Agentic 2026); Joint Commission RUAIH (jointcommission.org, 2026-05) + CHAI; FDA PCCP final & AI-DSF lifecycle draft (fda.gov); OpenTelemetry GenAI SemConv (2026); Colorado SB 189 (delayed to 2027). Full URLs retained in the audit working notes.*
