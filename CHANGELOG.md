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
