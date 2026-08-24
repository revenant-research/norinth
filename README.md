# Norinth

Norinth is an open-source platform for keeping track of the AI systems your
organization runs and showing that they are under control. It reads the
telemetry your applications already produce — model calls, tool calls,
retrievals, guardrail checks, evaluation results — and turns that into a live
picture of your AI: what is running, who is responsible for it, what evidence
backs it, and what decisions have been made about it.

You run Norinth on your own infrastructure. There is no hosted version and no
paid tier, and using it does not require an account with anyone. Everything in
this repository is licensed under [Apache-2.0](LICENSE). Norinth is a product of
[Revenant Research](https://www.revenantresearch.com/).

If you just want to see it working, jump to
[Try it out](#try-it-out). If you want to understand what it does first, keep
reading.

## The problem it solves

Once an organization starts using AI in production, people begin asking
questions about it: Which models are we running, and where? Who signed off on
this system? What data does it touch? What happens when it gives a bad answer?
How do we know any of this is actually being managed? Auditors, regulators, and
internal risk teams all ask some version of these questions.

The usual way to answer them is a questionnaire — a spreadsheet or a form that
someone fills in by hand. That approach has two problems. It is out of date the
moment it is saved, and it only describes the systems people remembered to write
down. The AI a team spun up last week to triage support tickets is not on the
list.

Norinth answers the same questions a different way. Instead of asking people to
describe their AI, it watches the AI run and builds the answer from what it
observes. Because the record comes from real traffic, it stays current on its
own, and it includes the systems nobody registered.

## What Norinth gives you

- **An inventory.** Every application, model, provider, workflow, and agent that
  has actually run, discovered from telemetry. Systems that show up in the data
  but were never formally registered are flagged, so you can see your "shadow
  AI" instead of guessing at it.

- **Control evidence.** Norinth maps what it observes to the requirements of the
  frameworks teams are usually measured against — NIST AI RMF, ISO/IEC 42001,
  the EU AI Act, and SOC 2 — and shows how much of each is satisfied and where
  the gaps are. It also produces a machine-readable AI bill of materials
  (CycloneDX) of the models and components in use.

- **Ownership and review.** You can tier each system by risk, name an
  accountable owner, and route reviews to the right role. Decisions require
  maker–checker separation: the person who submits a change cannot be the one
  who approves it, and administrators cannot approve their own work.

- **Release gates.** A deployment can be blocked from shipping until it has the
  evidence you require — a linked prompt version and a signed, passing
  evaluation for that exact version. Your CI pipeline can check the gate before
  it deploys.

- **An audit packet.** A single export containing the inventory, framework
  coverage, every decision with its rationale, incidents, release gates, and a
  tamper-evident (hash-chained) audit trail that an auditor can verify
  independently.

## How it works

There are two pieces, and they meet at one well-defined boundary.

1. **The SDK** (or any OpenTelemetry pipeline) runs alongside your AI
   applications and reports what they do. The Python SDK, `norinth-logger`, is
   small and safe to add: it is observe-only, it never blocks or crashes your
   application if Norinth is down, and by default it sends hashes of prompts and
   responses rather than the text itself.

2. **The platform** receives that telemetry, builds the inventory and the
   evidence from it, runs the review and gate workflows, and serves the
   dashboard and the audit packet. It stores everything in a database you
   control — SQLite for trying it out, PostgreSQL for production.

The two never share code. They communicate only over a documented, versioned
HTTP protocol (`POST /v1/events/batch` for the SDK, `POST /v1/otel/traces` for
OpenTelemetry), described in
[`packages/python-sdk/PROTOCOL.md`](packages/python-sdk/PROTOCOL.md). That
boundary is what lets you send data from any language or any collector, and it
keeps the SDK small enough to read in one sitting.

## Try it out

This walkthrough takes about fifteen minutes and leaves you with a running
Norinth, some AI systems in the inventory, and a feel for how the pieces fit. You
need [Docker](https://docs.docker.com/get-docker/) installed.

### 1. Install and start it

On a laptop or a single VM:

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash
```

The installer generates every secret for you, starts PostgreSQL and Norinth in
containers, waits until the platform reports healthy, and then prints two things:
the URL to open and a temporary administrator login. (If you have
[cosign](https://docs.sigstore.dev/) installed, it also verifies the signature
on the container image before running it.)

### 2. Finish setup in the browser

Open the URL the installer printed. Because this is a brand-new instance, Norinth
shows a short setup wizard instead of the dashboard. It walks you through a few
short steps, and the ones that matter here are:

- Signing in with the temporary administrator login and choosing your own
  password.
- Naming your organization.
- Creating an **ingestion key** — the credential your applications will use to
  send telemetry. It is shown only once, so copy it somewhere safe. (More on
  what it is in [Key ideas](#key-ideas) below.)

The wizard also shows an instrumentation snippet pre-filled with this instance's
address and then waits for your first event to arrive.

### 3. Send it some data

Norinth is not interesting until data flows into it, so let's send some. The
quickest way is to make a single AI call through the SDK. In a fresh directory:

```bash
pip install norinth-logger openai
export NORINTH_ENDPOINT="http://localhost:8001"     # the address from step 1
export NORINTH_API_KEY="nrk_...paste_your_key..."   # the ingestion key from step 2
export OPENAI_API_KEY="sk-...your_openai_key..."
```

```python
# try_norinth.py
import os, norinth_logger as norinth
from openai import OpenAI

norinth.init(
    api_key=os.environ["NORINTH_API_KEY"],
    endpoint=os.environ["NORINTH_ENDPOINT"],
    project="getting-started",
    service="hello-norinth",
)

client = norinth.wrap(OpenAI())   # calls made through this client are recorded

reply = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello to Norinth."}],
)
print(reply.choices[0].message.content)
```

Run it (`python try_norinth.py`). The call goes to OpenAI as usual; on the way,
the wrapped client reports the model, latency, and token usage to your Norinth
instance. You do not have to change how your application works — wrapping the
client is the whole integration.

Don't have an OpenAI key handy? Any Norinth SDK method produces events, and the
example above already sends the SDK's own health event on startup, so a system
will appear even without the model call.

### 4. Look around

Go back to the dashboard and you will see `hello-norinth` show up as a system,
with the model call recorded under it. From here it is worth clicking through:

- **Inventory** lists the systems Norinth has seen. Yours will be there,
  discovered automatically rather than registered by hand.
- **Compliance** shows framework coverage. It will be mostly empty on a fresh
  install — that is the point; coverage reflects real evidence, and you have only
  sent one call so far.
- **Telemetry** shows the raw events, so you can confirm what arrived.

That is the whole loop: an application reports what it does, Norinth turns it
into an inventory and evidence, and you govern from there. Real use is the same
loop with more applications and the review, gate, and audit features layered on
top.

## Key ideas

A few terms show up throughout Norinth. In plain language:

- **Ingestion key.** The credential an application uses to send telemetry to
  your Norinth. You create it inside your own instance (the setup wizard, or
  **Identity & Integrations → ingestion keys**, or `POST /api/ingestion-keys`).
  It is prefixed `nrk_`, shown once, and tied to your organization, so telemetry
  sent with it can only ever be written to your own data. It is not an account
  or a key from any external service.

- **Organization (tenant).** Norinth is multi-tenant. Every key, user, and
  record belongs to one organization, and organizations cannot see each other's
  data.

- **Control and framework coverage.** A control is a specific requirement (for
  example, "evaluation evidence exists before release"). Norinth maps controls
  to the frameworks that name them and reports coverage as the share of the
  requirements it maps that are currently satisfied — not a claim about the whole
  regulation.

- **Release gate.** A checkpoint a deployment must pass before it ships. Norinth
  can require named approval and signed evaluation evidence bound to the exact
  version being released.

- **Audit packet.** A single export of everything an auditor would ask for,
  backed by a hash-chained audit trail they can verify.

## Running it for real

The one-command installer is meant for a laptop or a single VM. For production,
Norinth ships a Helm chart and signed, multi-architecture container images:

```bash
helm install norinth oci://ghcr.io/revenant-research/charts/norinth \
  --set postgres.url="$DATABASE_URL"
```

[`docs/operations.md`](docs/operations.md) covers deployment, the full list of
configuration variables, backups and restores, and upgrades. A few settings
matter before any non-local deployment — the administrator credentials, the
signing and encryption keys, and secure cookies — and they are listed in
[`SECURITY.md`](SECURITY.md).

## Running from source

If you want to develop against Norinth or read the code while it runs:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e packages/python-sdk
make build-frontend                       # builds the dashboard (needs Node 20)
export NORINTH_PLATFORM_DB=apps/platform/data/norinth.sqlite3
uvicorn app.main:app --app-dir apps/platform --reload --port 8001
```

Running from source with no administrator password set is "development mode",
which seeds a well-known `dev` ingestion key so the quickstart works without
minting one. To fill the dashboard with synthetic sample data in that mode:

```bash
export NORINTH_ENDPOINT=http://127.0.0.1:8001 NORINTH_API_KEY=dev
python scripts/seed_dashboard.py
```

Run the same checks CI does with `make lint` and `make test`.

## Repository layout

| Path | What it is |
|---|---|
| `apps/platform/` | The platform: the FastAPI server, the governance engine, and the React dashboard. |
| `packages/python-sdk/` | `norinth-logger`, the Python SDK, and the wire protocol (`PROTOCOL.md`). |
| `deploy/helm/` | The Helm chart for Kubernetes. |
| `scripts/` | The installer, backup and restore, and helper scripts. |
| `docs/` | Operations and threat-model documentation. |

## Documentation

- [`docs/operations.md`](docs/operations.md) — deploy, configure, upgrade, back up.
- [`docs/threat-model.md`](docs/threat-model.md) — data flow, trust boundaries, and controls.
- [`SECURITY.md`](SECURITY.md) — the security model and how to report a vulnerability.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to build and contribute.
- [`packages/python-sdk/README.md`](packages/python-sdk/README.md) — the SDK in detail.

## A note on privacy

The SDK is observe-only by default: it records structured metadata and hashes of
inputs and outputs, not the raw text, and it never blocks your application. If
you deliberately turn on content capture (`NORINTH_CAPTURE_CONTENT=true`), the
SDK still redacts common secrets and identifiers before anything leaves your
process, and the platform can encrypt raw event bodies at rest. Because you run
the whole system, your telemetry never leaves your network.
