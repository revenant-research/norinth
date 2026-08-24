# Norinth

**Open-source AI governance from the telemetry your apps already produce.**

Norinth watches the calls your AI systems make and turns them into governance
you can show an auditor: a live inventory of every model, app and agent that ran,
reviews routed to named owners, releases that are blocked until the evidence
exists, and a tamper-evident audit trail you can export.

Everything here is [Apache-2.0](LICENSE) and runs on **your** infrastructure.
There is no hosted version, no paid tier, and adopting it requires no account
with anyone. Norinth is a product of
[Revenant Research](https://www.revenantresearch.com/).

---

## What you get

- **Inventory** — every application, model, provider, workflow and agent that
  actually ran, including the AI nobody registered.
- **Evidence** — control coverage mapped to NIST AI RMF, ISO/IEC 42001, the EU
  AI Act and SOC 2, plus a valid CycloneDX AI-BOM, all built from real calls.
- **Workflow** — tier each system, name an accountable owner, route reviews to
  the right role, and require maker-checker on every decision.
- **Release gates** — a deployment can't be approved until it has a linked
  prompt version and a signed, passing evaluation bound to that exact version.
- **Audit packet** — one export with the inventory, coverage, decisions with
  rationale, gates, incidents and a hash-chained audit trail your auditor can
  verify.

---

## 1. Install it (self-host)

You need Docker. On a laptop or a single VM:

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash
```

The installer generates every secret, starts PostgreSQL and Norinth, waits for
`/health`, and prints the URL and the administrator login. If `cosign` is
installed it verifies the image signature before running it.

Open the URL it prints. The first visit is a short setup wizard: claim the admin
account, name your organization, and create an ingestion key.

For Kubernetes, backups, upgrades and the full configuration reference, see
[`docs/operations.md`](docs/operations.md).

## 2. Send it data

Point your AI services at Norinth. The Python SDK is the quickest way:

```bash
pip install norinth-logger
```

```python
import os
import norinth_logger as norinth
from openai import OpenAI

norinth.init(
    api_key=os.environ["NORINTH_API_KEY"],   # the ingestion key from step 1
    endpoint="https://norinth.your-host",    # where you installed Norinth
    project="claims",
)

client = norinth.wrap(OpenAI())   # every model call this client makes is recorded
```

`NORINTH_API_KEY` is an **ingestion key you mint inside your own Norinth** — not
an account with anyone. Create one in the first-run setup wizard, or later under
**Identity & Integrations → ingestion keys** (or `POST /api/ingestion-keys`); it
is shown once, prefixed `nrk_`, and scopes every event to your tenant.
`NORINTH_ENDPOINT` is your instance's own URL. Running from source in dev mode, a
well-known `dev` key is seeded so you don't need to mint one.

The SDK is fail-open: if Norinth is unreachable, your application keeps running
and telemetry is retried (or spooled to disk if you set `NORINTH_SPOOL_DIR`).

**Already on OpenTelemetry?** Point any collector or LLM gateway at
`POST /v1/otel/traces` with the same key — no SDK required. The wire protocol is
documented in [`packages/python-sdk/PROTOCOL.md`](packages/python-sdk/PROTOCOL.md).

## 3. Govern

Back in the dashboard you'll see systems appear as events arrive. From there you
tier them, assign owners, route reviews, set release gates, and export the audit
packet from **Compliance**.

---

## Run from source (for contributors)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e packages/python-sdk
make build-frontend                       # compiles the dashboard (needs Node 20)
export NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3
uvicorn app.main:app --app-dir apps/platform --reload --port 8001
```

The compiled dashboard is a build artifact and is not committed; `make run`
builds it if missing. Without it the API still runs and `/` returns an explicit
"dashboard not built" page.

Running from source with no `NORINTH_SUPER_ADMIN_PASSWORD` set is "dev mode": a
well-known `dev` ingestion key (bound to the `tenant-local` tenant) is seeded so
the quickstart works. To watch the dashboard populate with synthetic sample
data:

```bash
export NORINTH_ENDPOINT=http://127.0.0.1:8001 NORINTH_API_KEY=dev
python scripts/seed_dashboard.py
```

Run the checks the way CI does:

```bash
make lint        # ruff
make test        # pytest (SQLite; also runs against PostgreSQL in CI)
make build-frontend && (cd apps/platform/frontend && npm test)
```

`scripts/verify_live.py` exercises the full identity, RBAC and decision path
against a running instance.

---

## How it's built

Norinth is two programs that meet at **one seam**: a published, versioned HTTP
protocol (`POST /v1/events/batch`, `POST /v1/otel/traces`).

- The **SDK** (`packages/python-sdk/`) imports nothing from the platform. It is
  small, fail-open, and hashes prompts/responses by default (raw content capture
  is opt-in and redacted).
- The **platform** (`apps/platform/`) imports nothing from the SDK. It's a
  FastAPI server, a governance engine, and a React dashboard, backed by SQLite
  for evaluation or PostgreSQL for production.

This keeps the SDK tiny and auditable, lets other languages implement the
protocol, and lets the platform consume OpenTelemetry GenAI spans from any
gateway.

## Repository layout

| Path | What it is |
|---|---|
| `apps/platform/` | The platform: FastAPI server, storage, governance engine, React dashboard. |
| `packages/python-sdk/` | `norinth-logger`: the fail-open Python SDK and the wire protocol (`PROTOCOL.md`). |
| `scripts/` | `install.sh`, backup/restore, and seeding/verification helpers. |
| `deploy/helm/` | The Helm chart for Kubernetes. |
| `docs/` | Operations, threat model, strategy. |

## Documentation

- [`docs/operations.md`](docs/operations.md) — deploy, configure, upgrade, back up.
- [`SECURITY.md`](SECURITY.md) — security model and disclosure; [`docs/threat-model.md`](docs/threat-model.md) — data flow, adversaries, controls.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to build and contribute.
- [`CHANGELOG.md`](CHANGELOG.md) — change history.

## Safety defaults

The SDK is observe-only by default: it records structured metadata and hashes,
not raw content, and never blocks or crashes your application. Set
`NORINTH_CAPTURE_CONTENT=true` only in a controlled environment where raw
prompt/response capture is intended — even then, content is redacted and only
JSON-native values are kept.
