# Norinth

Norinth is an AI governance system split into three independently licensed
components with a clean separation of concerns. The split mirrors the product
strategy: an **open client** for trust and adoption, a **closed platform** that
holds the commercial value, and a **test harness** that simulates real traffic.

## Key documents

- [`AUDIT_AND_ROADMAP_2026.md`](AUDIT_AND_ROADMAP_2026.md) — security/architecture audit and phased remediation roadmap.
- [`docs/GTM_STRATEGY.md`](docs/GTM_STRATEGY.md) — go-to-market strategy (ICP, wedge, motion, pricing, competitive positioning).
- [`CHANGELOG.md`](CHANGELOG.md) — hardening history.

## Repository layout and licensing

| Zone | Path | License | Role |
|---|---|---|---|
| **Open SDK (client)** | `packages/python-sdk/` | Apache-2.0 | Runs inside a vendor's infra. Captures, redacts, signs, and ships telemetry. Auditable by design. Contains no moat. |
| **Platform (server)** | `apps/platform/` | Proprietary (commercial) | Ingests telemetry, maps it to governance frameworks, and serves the Enterprise Network. The commercial product. |
| **Demo apps (harness)** | `demo-apps/` | Apache-2.0 | Simulated customer services for end-to-end testing. Not part of the Platform. |

Each zone has its own `LICENSE` and `README.md`. See:
- `packages/python-sdk/README.md` and `packages/python-sdk/PROTOCOL.md`
- `apps/platform/README.md`
- `demo-apps/README.md`

## The one seam: the wire protocol

The only coupling between the open client and the closed platform is the
documented HTTP wire format (`POST /v1/events/batch`), specified in
`packages/python-sdk/PROTOCOL.md`. The boundary rules are enforced by
convention and verified to hold today:

- The **SDK** imports nothing from the Platform.
- The **Platform** imports nothing from the SDK (`app/schemas/events.py` is its
  own server-side validator for the protocol, intentionally duplicated rather
  than imported).
- The **demo apps** import only the open SDK and their own local observability
  adapter — never the Platform.

This is what makes the SDK safe to open while the Platform stays closed: they
are separate programs that meet only at a published, versioned protocol.

## Future repo split

Because there are no cross-imports, these zones can be lifted into separate
repositories with no code changes:

- `norinth-sdk` (public, Apache-2.0) ← `packages/python-sdk/` + the protocol spec
- `norinth-platform` (private, commercial) ← `apps/platform/`
- `norinth-demo-apps` (public, Apache-2.0) ← `demo-apps/`

## Run Locally

Use five terminals.

Terminal 1, start the platform:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r apps/platform/requirements.txt
export NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3
uvicorn app.main:app --app-dir apps/platform --reload --port 8001
```

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
