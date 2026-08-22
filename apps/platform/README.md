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
