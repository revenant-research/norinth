# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project follows
Semantic Versioning.

## [Unreleased]

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

### Added

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
