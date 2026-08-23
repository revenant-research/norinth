# Norinth Platform

**Proprietary and commercial (All Rights Reserved).** Not open source. See
[`LICENSE`](./LICENSE).

This is the closed, commercial component of Norinth — the server that receives
telemetry from the open [Norinth Logger SDK](../../packages/python-sdk/) and
turns it into governance evidence and the Enterprise Network. It is a separate
program from the SDK and shares only the public wire protocol
([`PROTOCOL.md`](../../packages/python-sdk/PROTOCOL.md)).

## What lives here (the commercial moat)

- **Ingestion** (`app/ingestion/`) — receives and verifies signed event batches
  at `/v1/events/batch`.
- **Governance mapping engine** (`app/storage/governance_policy.py`,
  `app/services/governance.py`) — maps runtime telemetry to NIST AI RMF,
  ISO/IEC 42001, EU AI Act, and SOC 2 controls.
- **Entity & lifecycle processing** (`app/storage/`) — applications, workflows,
  deployments, incidents, prompts, and material-change fingerprinting.
- **AIBOM + Enterprise Network API** (`app/api/compliance.py`) — CycloneDX AIBOM
  generation and the cross-tenant `/api/network/vendors` endpoint.
- **Authorization** (`app/services/authorization.py`) — roles including
  `ENTERPRISE_SUBSCRIBER` (the paid network access tier).
- **Dashboard / buyer UI** (`app/dashboard/`, `frontend/`).

## Boundary rules

- The Platform MUST NOT import from the SDK package (`norinth_logger`). The only
  coupling is the wire protocol. (`app/schemas/events.py` is the Platform's own
  server-side validator for that protocol, intentionally duplicated rather than
  imported.)
- The SDK MUST NOT import from the Platform.
- Demo apps are a separate test harness (`../../demo-apps/`) and are not part of
  the Platform.


## Database backend

The platform runs on **SQLite by default** (zero configuration, for local
development) and on **PostgreSQL for production**. Select PostgreSQL by setting:

```bash
export NORINTH_DATABASE_URL=postgresql://user:password@host:5432/norinth
```

PostgreSQL gives the evidence store the properties enterprise buyers require —
multiple writers, replication/HA, point-in-time recovery, and managed
encryption — which SQLite (single-writer, file-local) cannot. The storage layer
is backend-neutral via `app/storage/db.py`, and the full test suite runs against
both backends in CI (`make test` for SQLite, `make test-postgres` with
`NORINTH_TEST_DATABASE_URL` set).

With Docker: `docker compose --profile postgres up` starts a PostgreSQL service;
point `NORINTH_DATABASE_URL` at it in `docker-compose.yml`.

## Schema migrations

Schema changes are versioned (`app/storage/migrations.py`) and recorded in a
`schema_migrations` table. Pending migrations run automatically at startup and
can be applied explicitly with `make migrate` (prints the backend, applied
versions, and anything pending). Super admins can inspect the same status at
`GET /api/admin/schema`. Every migration runs identically on SQLite and
PostgreSQL. Keep migrations additive (expand/contract) so a running release
stays compatible with the next one's schema.

## Ingestion authentication

Telemetry ingestion (`POST /v1/events/batch`) authenticates with a **per-tenant
API key** presented as `Authorization: Bearer <key>`. The tenant is derived from
the key, never from the event payload — a batch that claims a different tenant is
rejected. Organization admins create and revoke keys via `/api/ingestion-keys`
(the plaintext key is returned only once, at creation).

In local development (when `NORINTH_SUPER_ADMIN_PASSWORD` is unset) a well-known
`dev` key bound to `tenant-local` is seeded so the quickstart works out of the
box. Set `NORINTH_SIGNING_SECRET` to additionally require HMAC-signed batches.

## Run

```bash
pip install -r requirements.txt
export NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3
uvicorn app.main:app --app-dir apps/platform --reload --port 8001
```

Or via Docker:

```bash
docker compose up --build
```
