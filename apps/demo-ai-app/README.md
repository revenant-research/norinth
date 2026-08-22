# Helpdesk Assistant (demo service)

A small multi-tenant customer support API that uses LLMs to summarize tickets,
draft replies, and recommend a priority. It exists to demonstrate how Norinth is
added to an **existing** application, rather than an application being built
around Norinth.

## The integration principle

The product code in this service has **no knowledge of Norinth**:

- `main.py`, `assistant.py`, `store.py`, `models.py`, and `config.py` contain
  zero telemetry calls.
- All Norinth wiring lives in `observability.py` and is activated by a single
  line in `main.py`: `observability.install(app)`.

Delete that one line and the service behaves identically, just without emitting
telemetry. This is the same change a real team makes when adopting the SDK:
install the package, set the application identity once at startup, and let
auto-instrumentation capture provider calls and request traces.

The request models carry `tenant_id` and `user_id` because this is a real
multi-tenant B2B service that scopes data and authorizes agents by those fields.
Norinth recognizes them automatically; the application does not pass anything to
the SDK on a per-request basis.

## Run it

```bash
pip install -r requirements.txt

# Provider credentials (the app calls these directly; the SDK captures the calls)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Where to send telemetry (defaults to http://localhost:8001)
export NORINTH_ENDPOINT=http://localhost:8001
export NORINTH_PROJECT=norinth-sandbox
export NORINTH_ENVIRONMENT=production

uvicorn main:app --reload --port 9000
```

## Exercise the endpoints

```bash
curl -X POST localhost:9000/v1/tickets/T-1001/summary \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"acme","user_id":"agent-7"}'

curl -X POST localhost:9000/v1/tickets/T-1002/triage \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"acme","user_id":"agent-7"}'
```

Each call produces a request trace and a captured model call in Norinth,
attributed to the `Helpdesk Assistant` application and the calling tenant.
