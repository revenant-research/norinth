# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
Semantic Versioning.

## [Unreleased]

### Security

- **Every GitHub Action is pinned to a full commit SHA.** Workflows previously
  referenced mutable tags, so whoever owned an action could change what ran
  inside the release job that signs images and publishes the SDK. Dependabot
  updates the SHAs.
- **`main` and the release tags are protected.** `main` takes pull requests
  only, with the CI and CodeQL checks required, no force-push, no deletion and
  linear history. `v*` tags cannot be moved or deleted once pushed, so a
  published release always corresponds to the commit it was built from.
- **PyPI publishing runs in a gated environment.** The `pypi` environment
  requires a maintainer's approval and only accepts `v*.*.*` tags.
- Dependabot alerts, Dependabot security updates, and secret scanning push
  protection are enabled on the repository.

### Changed

- **The SDK says at startup when it may drop evidence.** Durable delivery is
  off by default: a batch that fails every retry is dropped, and until now the
  only signal was a warning at the moment of the drop, in the host
  application's logs. The SDK now logs one warning when it starts without a
  spool, naming `NORINTH_SPOOL_DIR` and `NORINTH_DURABLE`, and every
  `sdk.health` event reports `durable`, `spool_configured` and a `spooled`
  counter so the posture is visible on the platform. Both quickstarts now
  mention the flags. The default is unchanged.

### Added

- OpenSSF Scorecard runs weekly and on push to `main`, publishing supply-chain
  results to the Security tab and the README badge.
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), a CODEOWNERS file, a pull
  request template, and issue forms for bug reports and feature requests.
- **Governance policy engine.** Each organization can declare its governance
  rules as a versioned document: how many approval stages each risk tier
  needs and which roles decide them, sequence or parallel ordering, per-tier
  and vendor recertification clocks, per-environment release-gate evidence
  (attested-evals requirement), extra typed intake fields, and a vendor
  registry reviewed through the same stage machinery. The trust rules stay
  fixed: the submitter never decides, no person decides two stages of one
  subject, decisions stay terminal and append-only, and gates only tighten.
  Every stage record and gate snapshot pins the policy version that governed
  it, activations are hash-chained in the audit log with a diff summary, and
  the audit packet gains a `governance_policy` section plus the stage and
  vendor records. In-flight reviews keep the policy they started under. The
  seeded platform default reproduces the previous fixed workflow exactly, so
  an install that never authors a policy is unchanged.
- **Notifications follow the path.** Reviewers are notified when their stage
  opens and when the queue routes a review to them, reminded when it is
  overdue, administrators are alerted on escalation, the submitter hears the
  final decision exactly once however many stages decided it, and vendor
  approvals announce their own expiry. All through the existing outbox:
  email plus signed webhooks, recipients resolved from role assignments.
- **Vendor governance proven by telemetry** (`RISK-VND-001`): a model
  provider observed in production with no approved vendor entry, or a model
  outside a vendor's approved list, raises a finding on every application
  using it; lapsed vendor approvals flip to `recertify_due` on the
  maintenance clock and stop covering their providers.
- **Policy builder UI** under Setup: each approval path is edited directly as
  its pipeline of steps (role, label, order, add and remove in place), read
  back as a plain-language sentence, and wired to live state: systems per
  tier, reviews in flight, and warnings when a path names a role nobody
  holds. One primary action reviews the changes in plain terms and puts them
  in force; history keeps every version with its hash, per-version change
  summaries, and the raw document behind a disclosure for auditors. A new AI
  vendors page joins observed provider usage to the registry, review pages
  render multi-stage checklists with per-stage decisions, and the intake form
  asks the policy's extra questions with the projected risk tier shown.

## [0.3.0] - 2026-08-30

### Added

- **Organizations can require MFA.** A per-organization security policy walls
  unenrolled local-password accounts into the enrollment flow (their password
  login keeps working, so flipping the flag can never strand an organization);
  SSO/SCIM accounts are exempt, and the administrator turning it on must be
  enrolled first. (#118, restored in #123)
- **TOTP multi-factor authentication** for every local-password account, the
  platform administrator included (RFC 6238, no new dependency). The password
  step on an enrolled account issues a short-lived challenge instead of a
  session; codes are single-use; secrets are encrypted at rest and recovery
  codes are hashed, single-use, and shown exactly once. An organization
  administrator can reset a locked-out member's MFA; the platform operator
  deliberately cannot, so an operator password reset no longer opens an
  enrolled account. (#113)
- **Session idle timeout** (`NORINTH_SESSION_IDLE_MINUTES`, default 30, `0`
  disables) alongside the absolute lifetime; idle sessions are deleted, and
  sessions from before the upgrade age out on their creation time. (#110)
- **Access and failure auditing**: failed logins (with source IP and tenant
  attribution), one lockout event per lockout, reads of the record-level
  events view, reads of the audit trail itself, AI-BOM exports, and operator
  previews of a tenant's data footprint — visible to that tenant. (#109)
- **`/health/ready`**: readiness now includes a database round-trip, so a pod
  that cannot reach its database leaves the load balancer instead of serving
  errors; `/health` stays database-free for liveness. Helm and Compose point
  at it. (#111)
- **Telemetry from a retired system is now a finding** (`RISK-LCY-001`), as
  the system hub always claimed: events observed after retirement raise an
  open finding with the late events as evidence. (#114)

### Fixed

- **The SDK content boundary now covers the structured emitter channels.**
  With capture off, `agent_run(steps=)`, `model_call(usage=)`,
  `guardrail(matched_rules=)` and caller-supplied `error=` payloads passed
  application data to the wire verbatim; a step's input/output is exactly
  where an agent's observations end up. Structural labels the platform reads
  (step tool names, token counts, identifier-shaped rule ids, error types)
  still arrive; everything else is summarized, and mapping key names are
  redacted everywhere. (#107)
- **Content fingerprints are keyed on a default install.** Without
  `NORINTH_SIGNING_SECRET` the SDK emitted bare SHA-256 digests, which are a
  lookup table for low-entropy content such as record numbers. The key now
  derives from the api key when no signing secret is set; digests change on
  upgrade for previously-unkeyed installs, and rotating the api key unlinks
  old fingerprints unless a signing secret is pinned. (#108, restored in #122)
- **Scope listings are tenant-scoped.** `/api/scopes` named every tenant's
  projects and environments to any signed-in tenant. (#106)
- **Decisions and exceptions are append-only.** Resubmitting an identical
  decision no longer rewrites its timestamp, and replaying an identical
  exception no longer resurrects a lapsed waiver. (#112)
- **Framework coverage includes detection rules.** Coverage was built only
  from the control library, silently dropping the OWASP agentic family that
  lives on risk rules; an open finding now marks its requirement as a gap
  regardless of assessments. The per-tenant audit packet also reports the
  tenant's own audit entry count instead of the platform-wide chain length.
  (#114)
- **An empty AAD binding on a stored secret is an error**, not a silent
  downgrade to unauthenticated context. (#115)
- The change-password screen enforced 8 characters client-side while the
  platform requires 12. (#110)
- **The content boundary now covers application `metadata`.** With
  `capture_content` off, the SDK hashed prompts and completions but passed
  `metadata` through verbatim, so an application that put a patient name or an
  MRN in it wrote that value to storage on an install that had explicitly turned
  capture off. Metadata is now treated as content: a fixed set of governance
  labels passes through (redacted, length-capped) and every other key is reduced
  to a type+hash summary. `NORINTH_METADATA_ALLOWLIST` opts individual keys back
  into the clear.
- **Incident descriptions obey the content boundary.** They were captured
  unconditionally, on the reasoning that a governance record needs the narrative.
  They are now hashed unless `NORINTH_CAPTURE_INCIDENT_DETAILS=true`. The
  incident `title` stays readable — it labels the incident in every list and
  alert — but is redacted and capped at 200 characters.
- **Raw event bodies are encrypted at rest by default.** Encryption was opt-in
  via `NORINTH_ENCRYPT_RAW_EVENTS=1`, so an install with a secret key configured
  still wrote captured content in plaintext until someone found the flag. It now
  follows the key; `NORINTH_ENCRYPT_RAW_EVENTS=0` is an explicit opt-out, and a
  keyless install still stores plaintext because encryption fails closed.
- **AI BOM vendor attribution is correct and deterministic.** Models and
  providers were collected into two independent sets and every model was then
  attributed to `next(iter(providers))`, so a system using two vendors
  mis-attributed at least one model, and which one changed with the interpreter's
  hash seed. Models now carry the `(provider, model)` pair their telemetry named,
  and the document is byte-identical across hash seeds.
- **OIDC endpoints must be HTTPS.** Discovery accepted whatever endpoints the
  document returned, so a hostile or tampered response could point the token
  exchange at an HTTP URL and receive the client secret and PKCE verifier in
  cleartext. Endpoint schemes are now validated at discovery and re-validated at
  use, and the document's `issuer` must match the configured one.
- **SSO and SAML state cookies are proxy-aware.** They decided `Secure` from
  `request.url.scheme`, which is HTTP behind a TLS-terminating proxy. They now
  use the same signal as the session cookie.

### Added (operations)

- **`NORINTH_DURABLE`.** Delivery defaults are tuned for observability — async,
  fail-open, bounded queue — and drop events when the queue fills with no spool
  configured. A deployment treating telemetry as evidence can set this to refuse
  to start without `NORINTH_SPOOL_DIR`, failing at boot rather than at audit.
- **Metrics and structured logs.** `GET /metrics` serves Prometheus
  text-format series (request rates and latency by route template, events
  accepted per tenant, audit-append duration, notification-outbox depth),
  authenticated by `NORINTH_METRICS_TOKEN` or a platform-administrator
  session — never anonymous, because labels carry tenant ids.
  `NORINTH_LOG_JSON=1` emits one JSON object per log line with request ids
  (accepted on `X-Request-ID`, returned on every response), and every
  audit-chain append also streams to the `norinth.audit` logger so a SIEM
  sees security events without polling the database. (#120)

### Changed

- **PostgreSQL connections are pooled and multi-worker is supported.**
  Storage calls reuse pooled connections (~30% off per-batch ingest cost;
  `NORINTH_PG_POOL_SIZE`), `NORINTH_WEB_CONCURRENCY` sets uvicorn workers
  (PostgreSQL required above 1), and `scripts/loadtest.py` lets any
  deployment measure itself — indicative laptop numbers are documented
  (~200 accepted events/s sustained with encryption at rest on). The
  harness also caught and fixed an unbounded evidence set on derived risks
  that made every matching event rewrite an ever-growing row. (#121)
- **Ingest cost no longer grows with stored history.** Accepting a batch
  recomputed derived state by reading (and with encryption on, decrypting)
  each touched application's entire event history, twice. The request path
  now folds the batch into fingerprints and assessments at O(batch), with
  risk rules evaluated over indexed column aggregates; the full recompute
  remains as the rebuild path. Also fixes a correctness bug this surfaced:
  repeat usage of an already-known model read as a material change (payload
  entries were built without dedup), which could block release gates on
  routine traffic. (#119, restored in #124)
- Release prep for v0.3.0: the SDK's PyPI page links point at the real
  repository (they targeted a nonexistent one), versions bumped, and
  CONTRIBUTING documents the tag steps and the one-time PyPI
  trusted-publisher setup. (#117)

- **Base images are digest-pinned and Python dependencies are locked.** The image
  now installs `apps/platform/requirements.lock.txt` with `--require-hashes`
  (regenerate with `make lock`), and base images carry digests as well as tags,
  so the artifact that was reviewed is the artifact that ships.

## [0.2.1] - 2026-08-24

### Fixed

- **The audit chain survives an algorithm change.** Each audit row now records
  the hash algorithm that produced it, and verification dispatches on it, so a
  future change leaves existing rows verifiable instead of reading as tampered.
- **Upgrading keeps the installed port.** `install.sh --upgrade` read the port
  back from the existing `.env`, so upgrading an install on a non-default port no
  longer times out and reports failure for an upgrade that worked.

## [0.2.0] - 2026-08-24

The first release hardened for production use. It carries the security and
reliability work below, and the fixes found by installing the platform and
using it end to end: the container install, the first-run wizard, the SDK, the
CLI, the OpenTelemetry path, backup and restore, and the Helm chart.

### Security & reliability

- **Tenant isolation** is enforced end to end: every stored record — including
  the control library, risk rules, review-queue and owner policies, and all
  derived governance state — is bound to its tenant, so one organization can
  never read or overwrite another's data or evidence.
- **Audit trail integrity**: audit rows are hash-chained and HMAC-keyed, and
  concurrent writers are serialized so the chain cannot fork.
- **Release-gate evidence** is bound to the exact deployed version: a gate needs
  a linked prompt version and a signed, passing evaluation for that version, and
  a deployer cannot approve their own release.
- **Identity hardening**: SAML assertions require a matching bearer
  SubjectConfirmation, audience and validity window; OIDC and SAML flows are
  bound to the browser that started them; the Host header is validated where
  identity URLs are built; failed-login lockout is atomic and keyed to a
  trustworthy source IP; identity-federated (JIT/SCIM) users default to a
  read-only role.
- **Secrets & content**: stored secrets (SSO, webhooks) are encrypted at rest
  and fail closed without a key; passwords use PBKDF2-SHA256 at OWASP-current
  iterations and are re-hashed on login; captured content is redacted; the raw
  event body can be encrypted at rest.
- **Delivery**: the SDK retries and can spool telemetry to disk instead of
  dropping it; webhook signatures are timestamped and replay-resistant; the
  notification outbox is safe across multiple replicas; migrations are
  coordinated so concurrent replicas don't race on boot.
- **Robustness**: the ingest path runs off the event loop, rejects malformed
  and oversized batches, and never leaks a platform-wide count; unknown record
  ids return 404 instead of a 500; summary metrics and lists are computed and
  paged in SQL rather than capped in memory.
- **Hardening headers**: a default-deny Content-Security-Policy plus
  clickjacking, MIME-sniffing and referrer protections; the dashboard is fully
  self-contained (no third-party requests).

### Fixed — data loss

- **A failed backup no longer leaves something that looks like a backup.**
  `backup.sh` and `restore.sh` ran `docker compose` unconditionally and failed
  on hosts that provide the standalone `docker-compose`. Backup failed after the
  output file had been created, leaving an empty but valid gzip — which passed
  restore's file/non-empty/gzip checks, so the documented recovery path was to
  drop the database and restore nothing. Backup now dumps to a `.partial`,
  verifies the dump contains SQL, and only then moves it into place; restore
  rejects a dump with no SQL before touching the database. CI takes a backup and
  restores it rather than only linting the scripts.

### Fixed — governance correctness

- **Release gates read live state.** A gate's blocker counts were only
  recomputed on ingest, so accepting a risk or waiving a control — the
  remediation the gate asks for — never cleared it until unrelated telemetry
  arrived. Approval now recomputes and records the evidence it checked.
- **A lapsed exception no longer approves a release.** Exceptions were expired
  only during ingest, so past its expiry date an acceptance stayed active and a
  release could be approved on it.
- **Clock-driven state advances on a timer.** A maintenance worker expires due
  exceptions and ages the review queue, so overdue reviews are raised and
  escalated in an application that has gone quiet. A PostgreSQL try-lock keeps
  replicas from double-notifying.
- **Telemetry retention is per organization.** It was a single global sweep with
  no tenant filter and no schedule. Each organization sets its own window; the
  default keeps everything, the floor is 7 days, only raw events age out, and
  every purge is audited.
- **Incident descriptions are readable.** The SDK summarised them with the
  setting that governs prompts and completions, so the record carried a SHA-256
  digest instead of an account of what happened. Always captured now, still
  redacted, and shown in the incident view.

### Fixed — first run and integrations

- The installer accepts either `docker compose` or `docker-compose`; it
  previously reported that Docker was required while Docker was running.
- The setup wizard's snippet called `init()` and claimed provider clients were
  auto-instrumented. They were not, so a new install produced no telemetry.
  Both onboarding snippets now call `autoinstrument()`, and the getting-started
  snippet no longer calls a function the SDK does not define.
- `norinth gate check` reports an unreachable platform as a configuration error
  (exit 3) instead of a traceback and exit 1, which is the code for "rejected" —
  CI could not tell a governance refusal from a network failure.
- The OpenTelemetry collector snippet sets `traces_endpoint`. It previously set
  `endpoint`, which otlphttp treats as a base and appends to, so spans went to a
  path the platform does not serve and nothing surfaced.
- The Helm quickstart sets `database.url`, the key the chart defines.

### Changed

- The pod runs with an immutable root filesystem (`readOnlyRootFilesystem`),
  verified against the image with `/tmp` and `/app/data` mounted.
- The operator endpoint for ageing out events requires an explicit `tenant_id`
  or `all_tenants: true`.

### Added

- **Identity provider setup documentation**: the OIDC redirect URI, the SAML SP
  metadata and ACS URLs, and the SCIM base URL and token — read off a running
  instance.
- Cross-tenant regression coverage for the endpoints that load a record by id,
  and regression tests for each behavioural fix above.


- **`norinth` CLI** (SDK package): `init` (writes `NORINTH_*` to `.env`,
  detects AI clients), `doctor` (reachability, key validity, a test event, and a
  plain diagnosis of failures), `gate check --deployment --version [--wait]`
  (CI enforcement: exit 0 only when the release gate is approved), and
  `attest keygen|sign`.
- `GET /v1/gates/check` — read-only, ingestion-key-authenticated, tenant-bound
  release-gate status for CI.
- **Notifications**: an email + signed-webhook outbox with a background delivery
  worker, per-organization webhooks (JSON or Slack), and single-use invite links.
- **Role-shaped Home** and activity-grouped navigation: everyone sees what needs
  them, and administrators see organization posture.

## [0.1.0] - 2026-08-23

First open-source release: the self-hosted AI governance platform, the Python
SDK, the one-command installer, a Helm chart, and signed container images.

### Added

- **Platform** (`apps/platform/`): FastAPI server, governance engine, and React
  dashboard. Multi-tenant with permission-based RBAC and maker-checker on
  decisions. Ingests SDK events and OpenTelemetry GenAI traces; builds a live
  inventory of applications, models, providers, workflows and agents; maps
  control evidence to NIST AI RMF, ISO/IEC 42001, the EU AI Act and SOC 2;
  routes reviews to owners; gates releases on evidence; and exports an audit
  packet backed by a hash-chained audit trail. SQLite for evaluation,
  PostgreSQL for production.
- **First-run setup wizard**: a fresh install opens a short wizard — claim the
  admin account, name your organization, create an ingestion key, and instrument
  your first application.
- **SDK** (`packages/python-sdk/`): `norinth-logger`, a fail-open, observe-only
  Python client that hashes prompts and responses by default and speaks the
  documented wire protocol (`PROTOCOL.md`).
- **Installer** (`scripts/install.sh`): one command that generates every secret,
  starts PostgreSQL and Norinth, verifies the image signature when cosign is
  present, and prints the URL and administrator login.
- **Helm chart** (`deploy/helm/norinth`): stateless Deployment with probes, a
  non-root security context, PDB, Service, Ingress, and chart-managed or
  existing Secrets.
- **Release pipeline** (`.github/workflows/release.yml`): on a `v*` tag, builds
  the multi-arch image, scans it, then signs it with cosign (keyless), attaches
  an SPDX SBOM and build-provenance attestation, publishes the Helm chart and
  the SDK, and creates a GitHub Release.
- **Documentation**: `docs/operations.md` (deploy, configure, upgrade, back up)
  and `docs/threat-model.md` (data flow, trust boundaries, controls, residual
  risk).
