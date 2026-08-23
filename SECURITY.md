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

## Hardening program

This repository is undergoing a structured security-hardening program tracked in
[`AUDIT_AND_ROADMAP_2026.md`](./AUDIT_AND_ROADMAP_2026.md). Known issues being
remediated (in priority order) include ingestion authentication and tenant
binding, deployment-gate integrity, separation of duties, transactional
ingestion, and SDK transport resilience. Do not deploy to production until the
Phase 0 items in that roadmap are complete.

## Defaults you must change before any non-local deployment

- `NORINTH_SUPER_ADMIN_EMAIL` / `NORINTH_SUPER_ADMIN_PASSWORD` — set these; the
  documented dev default (`admin@norinth.local` / `norinth-admin`) is for local
  use only.
- `NORINTH_SIGNING_SECRET` — required to authenticate SDK ingestion batches.
- `NORINTH_SECRET_KEY` — 32-byte base64 master key used to encrypt stored
  secrets (SSO client secrets) with AES-256-GCM. Without it, secrets are stored
  in plaintext (development only).
- `NORINTH_COOKIE_SECURE=1` — set behind TLS so session cookies are `Secure`.
