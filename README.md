# Norinth

**Open-source AI governance from runtime evidence.** Norinth watches the AI your
organization actually runs — model calls, agents, tools, retrievals, guardrails,
evaluations — and turns that telemetry into a live inventory, control evidence,
enforceable release gates, and an audit packet you can hand to an auditor.

[![CI](https://github.com/revenant-research/norinth/actions/workflows/ci.yml/badge.svg)](https://github.com/revenant-research/norinth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/revenant-research/norinth)](https://github.com/revenant-research/norinth/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

You run Norinth on your own infrastructure. There is no hosted version, no paid
tier, and no account with anyone — everything in this repository is
[Apache-2.0](LICENSE). Norinth is a product of
[Revenant Research](https://www.revenantresearch.com/).

![The Norinth home view: what needs you, organization posture, and recent decisions](docs/images/home.png)

Jump to [Try it out](#try-it-out) to have this running in about fifteen
minutes, or take the tour first.

## The problem it solves

Once an organization uses AI in production, people start asking questions about
it: Which models are we running, and where? Who signed off on this system? What
happens when it gives a bad answer? How do we know any of this is actually
managed? Auditors, regulators, and internal risk teams all ask some version of
these questions.

The usual answer is a questionnaire — a spreadsheet someone fills in by hand.
It is out of date the moment it is saved, and it only covers the systems people
remembered to write down. The AI a team spun up last week to triage support
tickets is not on the list.

Norinth answers the same questions from evidence instead. It watches the AI run
and builds the answer from what it observes — so the record stays current on
its own, and it includes the systems nobody registered. Where a checkbox and
the telemetry disagree, the telemetry wins: **an open finding counts as a gap
no matter what a form says.**

> The screenshots below show a synthetic demo estate ("Meridian Health") seeded
> through the public ingestion API — the same path your applications use.

## The tour

### Every AI system that actually runs, including the ones nobody registered

The inventory is discovered from telemetry, not collected by survey. Systems
that appear in production traffic but were never registered are flagged as
unregistered — your shadow AI, made visible instead of guessed at.

![The AI systems inventory, with governance stage, risk tier, and unregistered systems flagged](docs/images/inventory.png)

Each system gets a hub: its lifecycle stage, accountable owners, what is
blocking it, and every model, workflow, risk, control, release, and incident
linked to it in one place.

![One AI system's hub: stage, blockers, models, workflows, risks and controls](docs/images/system-hub.png)

### Agent governance, reconciled at runtime

Register the agents you sanction with an accountable owner, an autonomy level,
and a tool allow-list. Every agent observed in telemetry is reconciled against
that registry: an unregistered agent, a tool used outside its allow-list, or an
agent combining untrusted input, sensitive data, and external actions without a
human checkpoint each raise a finding, mapped to the OWASP Top 10 for Agentic
Applications.

![Runtime agent posture: a registered agent with no issues, and a shadow agent raising an OWASP finding](docs/images/agents.png)

### Findings people have to answer, decisions people have to own

Risk findings are raised by the platform from what it observes — a missing
guardrail, an unreviewed vendor dependency, telemetry from a system recorded as
retired — and by people. Accepting a risk requires an owner, a compensating
control, and an expiry; the exception lapses on schedule and the finding
reopens. Reviews enforce maker–checker separation: the person who submits a
change can never be the one who approves it, and administrators cannot hold
decision roles at all.

![The risk register: findings with severity, evidence, and an accepted risk with an expiring exception](docs/images/risk.png)

### Release gates that block on evidence

Nothing ships without a gate. A deployment reported by your pipeline gets a
gate that stays closed until the evidence is there: no open risks, no missing
controls, no unreviewed material changes, a linked prompt version, and passing
evaluation evidence **bound to the exact version being released** — signed by
your CI's registered key, so a passing eval cannot be forged by anyone who
merely holds an ingestion key. `norinth gate check` in CI makes the gate a
required step.

![A release gate pending review, showing exactly which evidence is present and which is blocking](docs/images/release-gates.png)

### Compliance you can defend, because it is computed

Coverage of NIST AI RMF, ISO/IEC 42001, the EU AI Act, SOC 2, and the OWASP
agentic top 10 is computed from control assessments and detection rules — not
self-attested. The audit packet exports the inventory, the AI bill of materials
(CycloneDX), every decision with its rationale, and a hash-chained audit trail
an auditor can verify independently.

![Framework coverage computed from evidence, with outstanding requirements named](docs/images/compliance.png)

### The raw evidence, with a hard privacy boundary

Telemetry is inspectable down to the event — and what the events contain is
governed by the SDK's content boundary. By default prompts, completions,
metadata values, agent step inputs and outputs, tool arguments, and error
messages never leave your process as text: they arrive as keyed HMAC
fingerprints (never bare digests), while the governance labels the platform
actually reads pass through redacted and capped. Content capture is an explicit
opt-in, and raw bodies are encrypted at rest when a key is configured.

![The telemetry view: traces, model calls, guardrail decisions and eval results as reported](docs/images/telemetry.png)

### An audit trail that includes the reads — and access that holds up

Every decision, export, failed login, lockout, and read of record-level data
lands on the same hash-chained audit log, verifiable end to end. Every account
— the platform administrator included — can enroll TOTP multi-factor
authentication, and an organization can require it; sessions end after
inactivity, not just at an absolute lifetime.

![The hash-chained audit log](docs/images/audit.png)

![Account security: TOTP enrollment with single-use recovery codes](docs/images/security-mfa.png)

## Where it's going: the governance policy engine

Approval workflows differ by organization: a high-risk system at a health
system needs security review, then legal sign-off, then business acceptance; a
low-risk internal tool needs one reviewer. The next major capability makes that
configurable **without** becoming a workflow designer: a declarative, versioned
policy document — approval stages per risk tier, recertification cadence, gate
requirements per environment, custom intake fields, and a vendor registry
reconciled against observed provider usage. The policy itself becomes evidence:
every decision records the policy version that governed it, and the meaning of
"approved" (evidence present, maker ≠ checker, terminal, hash-chained) stays
fixed and machine-checkable.

The full design is in
[`docs/design/governance-policy-engine.md`](docs/design/governance-policy-engine.md).

## How it works

There are two pieces, and they meet at one well-defined boundary.

1. **The SDK** (or any OpenTelemetry pipeline) runs alongside your AI
   applications and reports what they do. The Python SDK, `norinth-logger`, is
   small and safe to add: it is observe-only, it never blocks or crashes your
   application if Norinth is down, and by default it sends keyed hashes of
   prompts and responses rather than the text itself.

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

(If the PyPI package is not available yet, the same wheel is attached to every
[GitHub release](https://github.com/revenant-research/norinth/releases) —
`pip install` the `.whl` from the latest one.)

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
with the model call recorded under it. From here it is worth clicking through
**AI systems**, **Compliance** (mostly empty on a fresh install — that is the
point; coverage reflects real evidence), and **Telemetry** to confirm what
arrived.

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
  --set database.url="$DATABASE_URL" \
  --set secrets.secretKey="$(openssl rand -base64 32)" \
  --set secrets.superAdminPassword="$(openssl rand -base64 24)"
```

[`docs/operations.md`](docs/operations.md) covers deployment, the full list of
configuration variables, backups and restores, upgrades, sizing (with a load-test
harness and measured numbers), and observability: a Prometheus `/metrics`
endpoint, JSON logs with request ids, and an audit stream a SIEM can consume.
A few settings matter before any non-local deployment — the administrator
credentials, the signing and encryption keys, and secure cookies — and they are
listed in [`SECURITY.md`](SECURITY.md).

## Running from source

If you want to develop against Norinth or read the code while it runs:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e packages/python-sdk
make build-frontend                       # builds the dashboard (needs Node 22+)
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
| `scripts/` | The installer, backup and restore, the load-test harness, and helper scripts. |
| `docs/` | Operations and threat-model documentation, design RFCs, and these screenshots. |

## Documentation

- [`docs/operations.md`](docs/operations.md) — deploy, configure, upgrade, back up, size, observe.
- [`docs/threat-model.md`](docs/threat-model.md) — data flow, trust boundaries, and controls.
- [`docs/design/`](docs/design/) — accepted design RFCs (key rotation, the governance policy engine).
- [`SECURITY.md`](SECURITY.md) — the security model and how to report a vulnerability.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to build, contribute, and cut a release.
- [`packages/python-sdk/README.md`](packages/python-sdk/README.md) — the SDK in detail.

## A note on privacy

The SDK is observe-only by default: it records structured metadata and keyed
hashes of inputs and outputs, not the raw text, and it never blocks your
application. Fingerprints are always an HMAC — never a bare digest that a
dictionary attack could reverse for short prompts or record numbers — keyed by
your signing secret, or derived from your api key when none is set. The content
boundary covers everything your application passes, not just prompts and
completions: `metadata`, agent steps, tool arguments and results, usage
payloads, matched guardrail rules, and error messages all obey it. With capture
off, only a fixed set of governance labels (`application_name`,
`workflow_name`, `use_case`, `model_purpose`, `user_id`, `conversation_id`,
`tenant_id`, and structural labels like a step's tool name) reaches the
platform in the clear, and everything else is hashed. Incident descriptions are
hashed on the same terms.

If you deliberately turn on content capture (`NORINTH_CAPTURE_CONTENT=true`), the
SDK still redacts common secrets and identifiers before anything leaves your
process. On the platform, raw event bodies are encrypted at rest whenever a
secret key is configured. Because you run the whole system, your telemetry never
leaves your network.

See [`packages/python-sdk/README.md`](packages/python-sdk/README.md) for exactly
what crosses the boundary, and how to widen or narrow it.
