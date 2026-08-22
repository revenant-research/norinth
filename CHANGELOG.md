# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project aims to adhere
to Semantic Versioning once it reaches a tagged release.

## [Unreleased]

### Added
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
