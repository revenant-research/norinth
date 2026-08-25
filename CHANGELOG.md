# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
Semantic Versioning.

## [Unreleased]

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
