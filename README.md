# Norinth

**Open-source AI governance from runtime evidence.** Norinth turns the
telemetry your AI applications already produce into a live inventory, routes
reviews to named owners, blocks releases that lack evidence, and produces the
audit packet your auditor, regulator and board ask for.

Everything in this repository is licensed under [Apache-2.0](LICENSE) and is
built to be run by you, on your infrastructure. There is no hosted version and
no paid tier. Norinth is a product of [Revenant Research](https://www.revenantresearch.com/).

## Get started in ten minutes

Laptop or single VM (Docker required):

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash
```

The installer generates every secret, starts PostgreSQL and the platform,
waits for `/health`, and prints the URL and the administrator login. The first
visit opens the setup wizard: claim the admin account, name your organization,
create an ingestion key, instrument one application, watch the first event
arrive.

Instrument a Python service:

```bash
pip install norinth-logger
```

```python
import os
import norinth_logger as norinth

norinth.init(api_key=os.environ["NORINTH_API_KEY"], endpoint="https://norinth.internal", project="claims")
# OpenAI and Anthropic clients are auto-instrumented from here.
```

Already on OpenTelemetry? Point any collector or LLM gateway at
`POST /v1/otel/traces` with the same key. See
[`packages/python-sdk/README.md`](packages/python-sdk/README.md) for the SDK and
[`docs/operations.md`](docs/operations.md) for production deployment
(Kubernetes, backups, upgrades, configuration reference).

## Key documents

- [`docs/operations.md`](docs/operations.md) — deploy, configure, upgrade, back up.
- [`SECURITY.md`](SECURITY.md) — security model and disclosure; [`docs/threat-model.md`](docs/threat-model.md) — data flow, adversaries, controls, residual risk.
- [`AUDIT_AND_ROADMAP_2026.md`](AUDIT_AND_ROADMAP_2026.md) — security/architecture audit and remediation roadmap.
- [`docs/GTM_STRATEGY.md`](docs/GTM_STRATEGY.md) — adoption strategy (ICP, wedge, open-source motion).
- [`CHANGELOG.md`](CHANGELOG.md) — change history.

## Repository layout

| Path | What it is |
|---|---|
| `apps/platform/` | The platform: FastAPI server, storage (SQLite for evaluation, PostgreSQL for production), governance engine, React dashboard. |
| `packages/python-sdk/` | `norinth-logger`: the zero-dependency, fail-open Python SDK and the wire protocol (`PROTOCOL.md`). |
| `demo-apps/` | Sample services that exercise the platform end to end. |
| `scripts/` | `install.sh`, backup/restore, seeding and verification helpers. |
| `docs/` | Operations, threat model, strategy. |

## The one seam: the wire protocol

The SDK and the platform are separate programs that meet only at a published,
versioned HTTP protocol (`POST /v1/events/batch`, `POST /v1/otel/traces`),
specified in `packages/python-sdk/PROTOCOL.md`:

- The **SDK** imports nothing from the platform.
- The **platform** imports nothing from the SDK (`app/schemas/events.py` is its
  own server-side validator, intentionally duplicated rather than imported).
- The **demo apps** import only the SDK.

This keeps the SDK tiny and auditable, lets other languages implement the
protocol, and lets the platform consume OpenTelemetry GenAI spans from any
gateway or collector.

## Run Locally

Use five terminals.

Terminal 1, build the dashboard once and start the platform:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r apps/platform/requirements.txt
make build-frontend   # compiles apps/platform/frontend -> app/dashboard/static (needs Node 20)
export NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3
uvicorn app.main:app --app-dir apps/platform --reload --port 8001
```

The compiled dashboard is a build artifact and is not committed; `make run`
builds it automatically if missing, and the Docker image builds it from source
in a multi-stage build. Without it the API still runs and `/` returns an
explicit 503 "dashboard not built" page.

Install demo app dependencies once:

```bash
source .venv/bin/activate
pip install -r demo-apps/requirements.txt
export OPENAI_API_KEY="your-openai-api-key"
export OPENAI_MODEL=gpt-4o-mini
export ANTHROPIC_API_KEY="your-anthropic-api-key"
export ANTHROPIC_MODEL=claude-haiku-4-5-20251001
```

Terminal 2, start Support Copilot:

```bash
source .venv/bin/activate
uvicorn app.main:app --app-dir demo-apps/support-copilot --reload --port 8002
```

Terminal 3, start Claims Review Assistant:

```bash
source .venv/bin/activate
uvicorn app.main:app --app-dir demo-apps/claims-review-assistant --reload --port 8003
```

Terminal 4, start Agentic Governance Assistant:

```bash
source .venv/bin/activate
uvicorn app.main:app --app-dir demo-apps/agentic-governance-assistant --reload --port 8004
```

Do not commit API keys or place them in source-controlled files. Each demo app is a separate customer-style service that reports to the same Norinth platform. Direct SDK calls live in each app's local observability adapter, not in provider clients or core workflow code.

Send a real OpenAI-backed support workflow:

```bash
curl -X POST http://localhost:8002/workflows/support-summary \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-local",
    "user_id": "user-local",
    "application_name": "Support Copilot",
    "use_case": "Summarize customer support tickets",
    "model_purpose": "Draft concise summaries for support agents",
    "content": "Customer cannot reset password after MFA enrollment and needs escalation."
  }'
```

Send a real Anthropic-backed claim workflow:

```bash
curl -X POST http://localhost:8003/workflows/claim-review \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-local",
    "user_id": "user-local",
    "application_name": "Claims Review Assistant",
    "use_case": "Review insurance claim notes for missing documentation",
    "model_purpose": "Assist analysts by identifying missing claim evidence",
    "content": "Claimant submitted photos and repair estimate, but no police report or signed loss statement is attached."
  }'
```

Send a real multi-provider agent workflow:

```bash
curl -X POST http://localhost:8004/workflows/agentic-governance-review \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-local",
    "user_id": "user-local",
    "application_name": "Claims Review Assistant",
    "use_case": "Review insurance claim notes for missing documentation",
    "model_purpose": "Assist analysts by identifying missing claim evidence",
    "content": "Claimant submitted photos and repair estimate, but no police report or signed loss statement is attached."
  }'
```

The request body is the test data. The apps do not seed dashboard rows or return canned AI output. The SDK auto-instruments supported provider clients to infer provider, model, operation, latency, token usage, and response metadata from each provider call. Governance context such as tenant, user, application, use case, and workflow is inferred from FastAPI request context; the apps do not wrap provider clients, decorate workflow functions, or send explicit Norinth metadata commands to provider calls. Event types that are not auto-instrumented yet, such as prompt releases, deployments, incidents, retrievals, tool calls, guardrails, evals, and agent runs, are emitted through each application's own observability adapter.

Open the platform dashboard:

```text
http://localhost:8001/
```

Run the live verification suite after both servers are running:

```bash
python scripts/verify_live.py
```

The verification script calls all three standalone demo apps, then asserts that applications, workflows, models, agents, tools, retrievals, guardrails, evals, prompt releases, deployments, incidents, risk candidates, control evidence, owner routing, protected decisions, and the resource graph were created from SDK events and normalized platform entities. It also proves deployment approval is blocked until a deployment gate has linked prompt version evidence and passing eval evidence.

## Safety Defaults

The SDK is observe-only by default. It records structured metadata and hashes for inputs and outputs, but not raw content. If the platform is down or the SDK transport fails, customer code should continue running.

Use `NORINTH_CAPTURE_CONTENT=true` only in a controlled local test environment when raw prompt and response capture is explicitly intended.
