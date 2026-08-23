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
  crash host application code, or (b) transmit raw prompt/response content when
  `NORINTH_CAPTURE_CONTENT` is not enabled.

## Security model

Norinth is multi-tenant and permission-based: every record is bound to its
tenant, administration roles are mutually exclusive from decision roles, and
governance decisions enforce maker-checker. The audit trail is hash-chained and
HMAC-keyed. See [`docs/threat-model.md`](./docs/threat-model.md) for the data
flow, adversaries, controls, and residual risk.

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
