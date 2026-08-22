# Norinth Demo Apps — Test Harness

**Apache-2.0.** A simulated environment for exercising the Norinth SDK and
Platform end to end. This is **test/development tooling, not part of the
commercial Platform** and not a product surface.

These apps stand in for real customer services. They install the open
[Norinth Logger SDK](../packages/python-sdk/), instrument themselves exactly as
a real integrator would, and emit live telemetry to a running Platform so the
ingestion, governance mapping, and dashboards can be validated against
realistic traffic.

## Separation

- Each app is a standalone FastAPI service with its own `app/` directory.
- They depend only on the open SDK (`norinth_logger`) and their own local
  `app/observability.py` adapter.
- They do **not** import the Platform (`apps/platform`), and the Platform does
  not import them. The only interaction is runtime HTTP telemetry over the
  documented wire protocol.
- They are licensed permissively (Apache-2.0) and can ship as integration
  examples; they carry none of the Platform's commercial code.

## Apps

| App | Provider | Port | Workflow |
|---|---|---|---|
| `support-copilot` | OpenAI | 8002 | `support.summary` |
| `claims-review-assistant` | Anthropic | 8003 | `claim.review` |
| `agentic-governance-assistant` | OpenAI + Anthropic | 8004 | `agentic.governance.review` |

## Run

```bash
pip install -r demo-apps/requirements.txt

# Provider keys are required for the demo apps to make real model calls.
export OPENAI_API_KEY="..."
export ANTHROPIC_API_KEY="..."

uvicorn app.main:app --app-dir demo-apps/support-copilot --reload --port 8002
uvicorn app.main:app --app-dir demo-apps/claims-review-assistant --reload --port 8003
uvicorn app.main:app --app-dir demo-apps/agentic-governance-assistant --reload --port 8004
```

> Provider keys belong to the demo apps (they make real OpenAI/Anthropic
> calls). The SDK and Platform never require provider keys. To populate a
> Platform instance without provider keys, use `scripts/seed_dashboard.py`,
> which emits telemetry through the SDK directly.

The request body is the test input; these apps do not seed dashboard rows or
return canned AI output.
