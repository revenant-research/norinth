# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository
(**Security → Report a vulnerability** at
https://github.com/revenant-research/norinth/security/advisories/new) with a
description, reproduction steps, and impact. Please do not open public issues
for security reports.

## Scope

- **Platform** (`apps/platform/`) — the server. Highest priority.
- **SDK** (`packages/python-sdk/`) — the open telemetry client. The SDK is
  observe-only and fail-open by default; report any path that can (a) block or
  crash host application code, or (b) transmit any caller-supplied content —
  prompts, completions, `metadata` values, incident narrative — when
  `NORINTH_CAPTURE_CONTENT` is not enabled. The documented exceptions that are
  captured by design are the governance labels listed in the SDK README and the
  incident `title`.

## Security model

Norinth is multi-tenant and permission-based: governance records, users, role
assignments, ingestion keys and identity configuration are all bound to a
tenant, and cross-tenant reads and writes are refused at the API. Administration
roles are mutually exclusive from decision roles, and governance decisions
enforce maker-checker. The audit trail is hash-chained and HMAC-keyed.

Three things "multi-tenant" should **not** be read to imply here:

- **Isolation is logical, not physical.** Every tenant shares one database, one
  secret keyring and one audit HMAC keyring. Separation is enforced in
  application code and covered by tests — not by separate schemas, separate
  databases or per-tenant keys. An operator who needs cryptographic or physical
  separation runs one install per tenant.
- **Role definitions are platform-wide.** *Who* holds a role is per tenant
  (`role_assignments`); *what* a role may do (`role_permissions`) is global by
  design. A tenant administrator cannot redefine a role's permissions. A
  subsidiary that needs different rules runs its own install.
- **The audit chain is global.** Rows from all tenants interleave in a single
  hash chain, so one tenant's segment cannot be verified or exported
  standalone without the neighbouring rows' hashes. (Tenant purge deliberately
  leaves `audit_logs` intact so the chain stays verifiable.)

See [`docs/threat-model.md`](./docs/threat-model.md) for the data flow,
adversaries, controls, and residual risk.

## Defaults you must change before any non-local deployment

- `NORINTH_SUPER_ADMIN_EMAIL` / `NORINTH_SUPER_ADMIN_PASSWORD` — set these; the
  documented dev default (`admin@norinth.local` / `norinth-admin`) is for local
  use only.
- `NORINTH_SIGNING_SECRET` — required to authenticate SDK ingestion batches.
- `NORINTH_SECRET_KEY` — 32-byte base64 master key used to encrypt stored
  secrets (SSO client secrets, webhook secrets) with AES-256-GCM. Secret storage
  fails closed without it, so set it; `NORINTH_ALLOW_PLAINTEXT_SECRETS=1` is a
  local-development-only opt-out.
- `NORINTH_COOKIE_SECURE=1` — set behind TLS so session cookies are `Secure`.
