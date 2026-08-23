# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project aims to adhere
to Semantic Versioning once it reaches a tagged release.

## [Unreleased]

### Changed
- **Dashboard bundle is no longer committed.** `apps/platform/app/dashboard/static/`
  is built from source by `make build-frontend`, by CI (uploaded as an
  artifact and then verified: a dedicated job checks the platform serves the
  built `index.html` and its assets, and that without a bundle `/` is an
  explicit 503 rather than a stale UI), and by a new Node build stage in the
  Docker image. The 400-line legacy inline "AIBOM viewer" fallback page was
  removed; a minified blob in review diffs and bundle merge conflicts go with
  it. `.dockerignore` added.

### Added
- **Server-side pagination on every list endpoint (audit L: unbounded lists).**
  `/api/events`, `/api/model-calls`, `/api/sdk-health`, `/api/traces`,
  `/api/audit-logs` and the entity lists (retrievals, tools, guardrails, evals,
  agents, risk register, control evidence, change events, review tasks,
  deployment gates, incidents, owner assignments, decisions, exceptions) accept
  `offset`/`limit` (default 200, max 1000; out-of-range values are rejected with
  422) and return a `page {offset, limit, total, has_more}` object next to the
  existing list key, so current clients keep working. Event- and audit-backed
  endpoints page in SQL (`LIMIT/OFFSET` + `COUNT`) instead of materialising the
  table; the trace index is no longer silently truncated to 100.
- **Windowed record lists in the UI.** `RecordList` mounts 25 cards at a time
  with "Show more / Show all" and a live-region footer that reports the server
  total ("Showing 25 of 1,200 records (200 loaded)"), so large tenants no longer
  render thousands of DOM nodes. Metric cards count the whole tenant via
  `page.total`. The Audit Log has a real Newer/Older server-side pager (50 per
  page) that resets when filters change.
- **Partial-failure tolerant dashboard load.** One failing list endpoint no
  longer blanks every view: the remaining data renders, a banner names the
  failed endpoints with a Retry action, and session loss (401) still signs the
  user out.
- **Accessibility sweep of the original workspace views (audit L: a11y).**
  Every placeholder-only control in the owner-assignment, exception,
  review-decision, release-readiness and incident-closure forms now has an
  accessible name; the sidebar is a labelled `navigation` landmark with
  `aria-current="page"`; a skip-to-content link precedes it; hash-route
  changes update `document.title` and move focus to the page heading; the
  workspace is `aria-busy` while loading; auth errors are `role="alert"`;
  detail routes (#gate/…, #incident/…) get their own heading/title instead of
  "Overview". `--faint` text colour raised from 2.8:1 to 4.6:1 (WCAG AA).
  axe-core (WCAG 2.1 A/AA + best-practice) reports zero violations across all
  16 tenant views and the gate/incident/risk/trace detail views in a live
  browser, and jsdom axe checks now run in vitest for the shell, record lists,
  audit log and agents views.

### Fixed
- **White-screen crash navigating between detail records.** `DetailRoute`
  re-rendered with the previous route's payload for one frame when the route
  kind changed (e.g. #gate/… → #incident/…), so `IncidentDetail` read
  `detail.incident.title` on `undefined` and React unmounted the whole app.
  Loaded records are now tagged with the route they belong to and detail views
  guard against a missing primary record. Regression test included.
- Version control for the repository (previously unversioned), with a hardened
  `.gitignore` excluding virtualenvs, `node_modules`, SQLite databases, build
  artifacts, and local secrets.
- Continuous integration (GitHub Actions): ruff lint, mypy (baseline), pytest
  for Python; TypeScript typecheck + build for the frontend.
- Test suite scaffold with a temp-database harness and baseline smoke tests for
  the platform and SDK.
- Developer tooling: `pyproject.toml` (ruff/pytest/mypy config), `Makefile`,
  `.pre-commit-config.yaml`, `requirements-dev.txt`, and `.env.example`.
- Governance docs: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- `AUDIT_AND_ROADMAP_2026.md`: full security/architecture audit and remediation
  roadmap.

### Security
- **SDK privacy hardening (H-12, H-13).** Content fingerprints are now HMAC-keyed
  when a signing secret is configured, so short/low-entropy prompts are no longer
  dictionary-reversible and hashes cannot be linked across tenants; hashing is
  also canonical (sorted-key JSON) instead of unstable `repr()`. Exception
  messages — which provider 4xx errors and application code routinely fill with
  PII/PHI — are hashed and length-reported by default and only emitted verbatim
  under `NORINTH_CAPTURE_CONTENT` (previously they shipped raw). Inferred
  governance context skips nested structures and caps value length so request
  content can't ride out under a governance label. Critical for HIPAA-adjacent
  deployments.

### Fixed
- **Frontend: audit-log filters now work.** `useResource` captured the first
  loader closure permanently, so applying a tenant/actor/action filter on the
  audit log was a silent no-op. It now always invokes the latest loader, with
  out-of-order-response and unmount guards.
- **Frontend a11y: confirmation dialog.** Removed the global Enter=confirm
  binding (a keyboard user on the Cancel button pressing Enter previously
  triggered the destructive action); Enter/Space now activate the focused button
  natively. Added a focus trap and focus return to the invoking control on close.

### Fixed
- **SDK auto-instrumentation coverage (H-14).** The SDK only patched the sync
  OpenAI Responses API and sync Anthropic `messages.create`, so the most widely
  used surface (`chat.completions`) and all async clients emitted no telemetry —
  an AI inventory built on it was silently incomplete ("negative assurance").
  Added `chat.completions.create` (sync + async), async Responses, and async
  Anthropic `messages.create`, via a new async patcher that awaits the coroutine
  and records the call only after it resolves (fixing the async
  fabricated-success bug). Usage normalization now maps the chat naming
  (`prompt_tokens`/`completion_tokens`) and cache tokens, not just the Responses
  naming (audit A5). All patches are import-guarded so missing/changed provider
  SDK internals never raise.

### Fixed / Hardened
- **SDK transport resilience (C-8).** A single non-serializable event (or a NaN
  score) used to crash `json.dumps` in the background worker, which had no
  exception handling, killing the thread permanently — after which every event
  queued then dropped while the health counters still reported zero failures.
  The worker loop is now fully guarded (no exception can terminate it),
  serialization is defensive (`default=str`, `allow_nan=False`, wrapped so a bad
  batch is dropped not fatal), a dead worker is restarted on the next enqueue,
  the worker is re-created after `fork()` (gunicorn/celery prefork), an `atexit`
  flush avoids tail loss, and the SDK logger gets a `NullHandler`. The
  `sdk.health` event now reports `thread_alive`, `queue_depth`, and
  `capture_content` so a stalled transport or raw-capture mode is visible
  instead of silently misreported (P7).

### Security
- **Constrained decision & status enums (M-2).** The generic decisions route
  accepted any string and wrote it verbatim as the target's status, so a holder
  of a decision permission could invent a status ("totally_done") and escape the
  review workflow; org user-creation and role-assignment accepted arbitrary
  status values. Decisions are now validated against the known workflow verbs
  (approve/reject/accept_risk/mitigate/waive/close), apply_decision_status
  ignores anything else defensively, and user/role statuses are constrained to
  their valid values.

### Fixed
- **Atomic inventory set-merge (H-11).** The application/model/provider inventory
  rows accumulate JSON sets via a read-modify-write (fetch, merge in Python,
  write back). Under concurrent ingest two batches could each read the old set
  and the second write clobber the first, dropping a provider/model from the
  inventory. Entity processing now runs inside an IMMEDIATE transaction so a
  concurrent batch waits for the write lock and reads committed state before
  merging. SQLite is single-writer regardless, so there is no added throughput
  cost.

### Fixed
- **Human decisions survive re-computation (B6).** Every ingest re-derives
  control assessments and risk findings; it used to `INSERT OR REPLACE` them
  back to `passing`/`missing`/`open`, silently reopening a risk a reviewer had
  accepted and clearing a waived control. Re-computation now preserves any
  reviewer-set terminal status (accepted, waived, mitigation_required, ...) while
  still refreshing the underlying evidence.

### Fixed / Hardened
- **Ingestion robustness (C-6, C-3).** A well-formed-but-incomplete event (e.g.
  a `prompt.event` or `deployment.event` missing `artifact_ref`) previously
  crashed ingestion with an unhandled 500 *after* a partial write. Events are
  now validated per type before any write and a malformed batch is rejected
  atomically with 422. Ingestion is idempotent: a unique (trace_id, span_id)
  index plus INSERT OR IGNORE means a retried batch is not double-counted, and
  the response reports the number actually accepted. The SQLite connection now
  uses WAL journaling and a 30s busy timeout so concurrent reads/writes don't
  fail with "database is locked". Added a composite index for the per-app
  evidence scans.

### Security
- **Deployment-gate integrity (C-2).** Deployment gates are never auto-approved.
  Previously a gate with no blocking evidence was written directly as "approved"
  with no human and no attribution, and the generic /api/decisions route could
  flip a gate to "approved" while bypassing the evidence guard — so a release
  could ship with zero sign-off. Now every undecided gate stays `pending_review`
  until a human approves or rejects it through the guarded /approve|/reject
  endpoints (which require linked prompt + passing eval evidence and record the
  actor, rationale, and timestamp), and /api/decisions rejects deployment_gate
  and incident target types (400), directing callers to the dedicated guarded
  endpoints. Also: /api/decisions now returns 404 (not 500) for an unknown
  target.

### Security
- **Per-IP login throttling (H-6 follow-up).** Failed logins are now throttled
  per source IP as well as per account (separate, higher threshold so a shared
  office NAT isn't blocked by a few typos). This closes the two gaps of
  per-account lockout alone: an attacker deliberately locking a victim out
  (targeted-lockout DoS) and spraying one password across many accounts from one
  source. X-Forwarded-For is honoured only behind a declared trusted proxy
  (`NORINTH_TRUST_PROXY=1`), so the header cannot be spoofed to dodge the
  throttle. Schema moves to a namespaced `login_throttle` table (migration 4).

### Added
- **SSO via SAML 2.0** (with an Identity & Integrations UI panel showing the SP metadata URL and ACS URL to import into the IdP). Alongside OIDC, organizations can now federate with
  SAML-only identity providers (ADFS, Okta/Entra SAML apps): SP-initiated Web
  Browser SSO with an HTTP-Redirect AuthnRequest and HTTP-POST Response,
  SP metadata at `/api/auth/saml/metadata`, and org-admin configuration at
  `/api/org/saml` (IdP entity id, SSO URL, signing certificate, JIT default
  role, optional email-domain restriction). Responses are parsed with a hardened
  XML parser and their signature verified (signxml) against the configured IdP
  certificate only — never one embedded in the message — then Issuer, Audience,
  InResponseTo (single-use), NotBefore/NotOnOrAfter, StatusCode, and the bearer
  SubjectConfirmation Recipient are validated. JIT provisioning shares the OIDC
  path (tenant-bound, non-admin default role, no password). Schema added as
  migration 3.

### Added
- **Compliance UI.** A new "Compliance" workspace view shows per-framework
  coverage (NIST AI RMF, ISO/IEC 42001, EU AI Act, SOC 2, OWASP Agentic, ...)
  with accessible progress bars toned by percentage and expandable lists of the
  specific outstanding requirements, plus one-click **audit-packet export**
  (timestamped JSON download) that surfaces the audit-trail integrity verdict
  and packet counts. Makes the evidence deliverables self-serve for reviewers
  and auditors. Verified live in the browser; 3 new component tests.

### Security
- **Stored secrets encrypted at rest.** Tenant OIDC client secrets are now
  encrypted with AES-256-GCM under a master key (`NORINTH_SECRET_KEY`, injected
  from a KMS/secret manager in production), bound to the tenant via associated
  data so a row cannot be transplanted between organizations. A database dump
  or backup no longer yields usable credentials. Legacy plaintext values are
  read transparently and re-encrypted on next write; a wrong key fails closed.
  The design is envelope-ready for a KMS data key (BYOK).

### Added
- **Versioned schema migrations (M1).** Schema changes are now an ordered,
  recorded history (`schema_migrations` table) instead of "run every CREATE/ALTER
  on every boot and swallow the errors". Migration 1 is the baseline (the
  storage modules' idempotent initializers), so existing and fresh databases
  converge; subsequent changes are numbered migrations that run once, in a
  transaction, identically on SQLite and PostgreSQL. `make migrate` applies and
  prints status; `GET /api/admin/schema` exposes backend, applied, and pending
  versions to platform admins.

### Added
- **Identity & Integrations UI.** Org admins can now self-serve enterprise
  identity from a new workspace view: configure **SSO** (issuer, client, JIT
  default role, optional email-domain restriction — with the exact redirect URI
  to register at the IdP and the users' sign-in link), create/revoke **SCIM
  provisioning tokens**, and create/revoke **SDK ingestion keys**. Secrets are
  shown exactly once in a dismissable reveal with copy-to-clipboard and never
  persist in the DOM (the audit flagged temp credentials lingering on screen).
  Discovery failures surface as a readable error. Verified live in the browser;
  3 new component tests (secret reveal, SSO submit, token create→reveal→revoke).

### Added
- **Agents UI + frontend test infrastructure.** A new "Agents" workspace view
  shows runtime posture (observed / registered / shadow / with-issues metrics,
  per-agent OWASP-mapped issue badges with the offending tools), a labeled
  registration form with autonomy-level descriptions and a capability-profile
  fieldset that warns inline when the profile forms the lethal trifecta, and
  the registry with permission-gated retire. `vitest` + Testing Library are now
  set up and run in CI; `useResource` was extracted to its own module and its
  stale-closure fix is locked in by a test.

### Added
- **Agentic-AI governance module.** An **agent registry** (`/api/agent-registry`)
  records every sanctioned agent with an accountable owner, an **autonomy level**
  (0 tool-assisted … 4 fully autonomous), a **tool allow-list**, its capability
  profile (untrusted input / sensitive data / external action), and whether a
  human checkpoint exists. On every ingest, observed `agent.run` / `tool.call`
  telemetry is reconciled against the registry (`/api/agents/posture`) to derive
  risk findings mapped to the **OWASP Top 10 for Agentic Applications**:
  unregistered "shadow" agents (ASI10), tool use outside the allow-list
  (ASI02/ASI03), the **lethal trifecta** — untrusted input + sensitive data +
  external action with no human checkpoint (ASI01/ASI09, Critical), and high
  autonomy without oversight (ASI09 / EU AI Act Art 14). Findings land in the
  risk register (preserving reviewer decisions), the audit packet, and an
  "OWASP Agentic" framework-coverage family. Grounded in the 2026 research
  (OWASP Agentic 2026, Microsoft agent failure taxonomy, Meta Rule of Two,
  Singapore MGF for Agentic AI).

### Added
- **SCIM 2.0 user provisioning.** Identity providers (Okta, Microsoft Entra ID,
  ...) can now create, update, and deprovision users automatically via a
  per-tenant SCIM endpoint (`/scim/v2`: ServiceProviderConfig, Users
  list/filter/paginate, create, get, replace, patch, delete). Bearer tokens are
  issued and revoked by org admins (`/api/org/scim-tokens`), hashed at rest.
  Deactivation suspends the account and revokes its sessions immediately (the
  record is kept for the audit trail); provisioned users get the tenant's
  non-admin default role and sign in via SSO. Automated deprovisioning is a
  SOC 2 CC6 / HIPAA 164.308(a)(3) control and a universal enterprise checklist
  item.

### Added
- **SSO via OpenID Connect with JIT provisioning.** Organizations can configure
  their identity provider (Okta, Entra ID, Auth0, ...) at `PUT /api/org/sso`,
  which runs OpenID discovery against the issuer. Users sign in through
  `/api/auth/sso/{tenant}/start` -> IdP -> callback. The flow uses the
  authorization-code grant with PKCE (S256), single-use state, and nonce
  binding; the id_token is verified (RS256 against the provider's JWKS; iss, aud,
  exp, nonce). New users are provisioned just-in-time inside the tenant with the
  configured default role — never an administration role (separation of
  duties) — and have no password, so the IdP is their sole authority. Optional
  email-domain restriction. SSO is table-stakes for every enterprise and
  health-system buyer.

### Added
- **PostgreSQL backend (C-5 / enterprise architecture).** The platform now runs
  on PostgreSQL by setting `NORINTH_DATABASE_URL` (SQLite remains the
  zero-config default for local development). A new backend abstraction
  (`app/storage/db.py`) provides the connection/cursor interface the storage
  layer already uses and translates the SQLite idioms at execution time
  (placeholders, `datetime('now')`, `INSERT OR IGNORE/REPLACE`, `AUTOINCREMENT`,
  `PRAGMA`), with per-statement savepoints to preserve SQLite's statement-level
  atomicity for the idempotent migrations. Review-queue and session date
  arithmetic moved from SQL to Python so it is identical on both backends. The
  full test suite runs against real PostgreSQL in CI (service container) as
  well as SQLite. This retires the audit's "SQLite is disqualifying at scale"
  finding and unblocks HA/replication/managed-encryption deployments.

### Added
- **OpenTelemetry GenAI ingestion.** New `POST /v1/otel/traces` accepts OTLP/HTTP
  JSON spans and maps the OpenTelemetry GenAI semantic conventions (`gen_ai.*`)
  to Norinth events — chat/completions/embeddings -> model.call, execute_tool ->
  tool.call, invoke_agent/workflow -> agent.run, retrieval/data-source ->
  retrieval.call — so telemetry from any OTel-instrumented framework or LLM
  gateway (LiteLLM, Portkey, Kong, Microsoft Agent Framework, Pydantic AI,
  Vercel AI SDK, ...) feeds the same governance pipeline as the first-party SDK.
  Key-authenticated and tenant-bound like SDK ingestion; non-GenAI spans are
  skipped. This is the "consume everyone's signals" ingestion path from the GTM.

### Added
- **Framework coverage crosswalk.** New `GET /api/compliance/framework-coverage`
  rolls the flat control assessments up into per-framework compliance posture
  (NIST AI RMF, NIST GenAI Profile, ISO/IEC 42001, EU AI Act, SOC 2): total
  mapped requirements, how many are satisfied by passing/waived evidence, the
  coverage percentage, and the specific outstanding gaps. Also embedded in the
  audit-evidence packet. Turns the audit's "framework string labels" into an
  actual crosswalk — a table-stakes governance capability.

### Added
- **Audit-ready evidence packet.** New `GET /api/compliance/audit-packet`
  assembles a single, self-contained export of a tenant's governance posture —
  inventory, framework-mapped control assessments, risk findings, governance
  decisions and exceptions, deployment approvals, incidents, material changes,
  the CycloneDX AI-BOM, and the tamper-evidence status of the audit trail — for
  an auditor or certification body (SOC 2, ISO 42001, EU AI Act, Joint Commission
  RUAIH). Named as a missing capability in the audit; a table-stakes
  evidence-automation feature.

### Added
- **Data retention & right-to-erasure (H-10).** New super-admin capability to
  permanently erase a tenant's data on offboarding (GDPR Art 17, CCPA deletion,
  HIPAA/BAA return-or-destroy): `GET /api/admin/organizations/{id}/data`
  previews the footprint and `POST .../purge` (type-to-confirm) deletes every
  tenant-scoped table plus the tenant's sessions and login records. A retention
  endpoint (`POST /api/admin/retention/purge-events`) ages out raw telemetry
  older than a configurable window. The tamper-evident audit log is deliberately
  retained (legal-basis records retention; deleting rows would break its
  integrity chain). Previously the only DELETE in the platform was for expired
  sessions.

### Security
- **Login lockout & CSRF defense-in-depth (H-6, H-8).** Failed logins are now
  throttled per email (default: 5 failures in 15 min locks the account for
  15 min, cleared on success), slowing credential stuffing / password spraying
  against well-known accounts. A CSRF middleware rejects cross-origin mutating
  /api/* requests by verifying the browser-sent Origin against the request host
  (requests without an Origin — non-browser clients that carry no victim cookie
  — are unaffected), complementing the cookie's SameSite=lax.

### Security
- **Tamper-evident audit log (H-9).** Every audit entry now carries a hash
  chained to the previous entry (row_hash = SHA-256(prev_hash || entry)). Any
  insertion, deletion, reordering, or field change breaks the chain and is
  detected by a new integrity check, exposed to platform admins at
  GET /api/admin/audit-logs/verify. The read-of-last-hash and the insert run in
  a single IMMEDIATE transaction so concurrent writes cannot fork the chain.
  This gives the trail the integrity property SOC 2 CC7.2, HIPAA 164.312(b), and
  21 CFR Part 11 auditors require.

### Security
- **Tenant isolation fails closed (H-1, H-2, H-4).** Authorization now enforces
  tenant match strictly: require_actor_scope denies a tenant-bound actor acting
  on a target that names a different tenant OR names none at all (previously it
  skipped the check whenever either side was NULL), and role_scope_matches
  requires an exact tenant match so a NULL-scoped role assignment can no longer
  act as a cross-tenant wildcard. GET /api/sdk-health is tenant-scoped again
  (the tenant filter had been dropped, leaking other tenants' telemetry), and
  the control-evidence query no longer folds every tenant's sdk.health events
  into one tenant's evidence set (now that C-1 stamps a tenant on them).

### Security
- **Separation of duties (C-4).** An org_admin can no longer unilaterally
  escalate to governance decision authority. Administration roles (org_admin)
  and governance-decision roles (governance_admin, risk_owner, control_owner,
  governance_reviewer) are now mutually exclusive: a role assignment that would
  give one user both is rejected (409). Administrators also cannot change their
  own role assignments (403) — another administrator must. And being the
  auto-assigned reviewer of a task no longer bypasses the required decision
  permission (B3).
- **Removed dangerous governance-plane endpoints (C-7, H-2).** `POST /api/users`
  and `POST /api/role-assignments` (on the tenant-governance router) authorized
  on `config.write` with no tenant scoping on the target, which let any holder
  overwrite arbitrary accounts including the super admin (a lockout DoS) and
  self-grant globally-scoped roles. User and role management now lives only on
  the properly-scoped org-administration plane (`/api/org/*`).

### Security
- **Server-side password-change enforcement (C-4).** `must_change_password` is
  now enforced by middleware: a user holding a temporary password can log in and
  change it, but is blocked (403) from every other `/api/*` endpoint until they
  do. Previously this gate existed only in the frontend, so a temporary password
  drove the whole API via curl indefinitely.
- **Session hardening (H-7).** Session tokens are stored as SHA-256 hashes (a DB
  or backup leak no longer yields replayable tokens); the session cookie is
  marked `Secure` in production (relaxed automatically for local HTTP dev, or via
  `NORINTH_COOKIE_SECURE`); and a password change revokes all of the user's
  existing sessions and rotates the current one.

### Security
- **Ingestion authentication & tenant binding (C-1).** Replaced the single
  hard-coded `Bearer dev` ingestion token with per-tenant API keys (hashed at
  rest, shown once at creation, revocable). The ingestion endpoint now derives
  the tenant from the authenticated key and enforces it on every event: a batch
  claiming a different tenant is rejected (403), and events omitting a tenant are
  stamped with the key's tenant (no NULL-tenant rows from authenticated ingest).
  Org admins manage their keys via `/api/ingestion-keys`. A well-known `dev` key
  (bound to `tenant-local`) is seeded in development only, keeping the local
  quickstart working without allowing cross-tenant forgery.

### Fixed
- Dockerfile: corrected the `requirements.txt` COPY path (the image previously
  failed to build), added a non-root runtime user and a `HEALTHCHECK`.
- docker-compose: aligned the database env var to `NORINTH_PLATFORM_DB` (the
  variable the application actually reads); data previously landed on an
  ephemeral path.
- Exception chaining (`raise ... from`) across API error handlers.
