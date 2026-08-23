# Norinth — Adoption Strategy (open source, self-hosted)

*Revised August 2026. Supersedes the open-core plan.*

## 1. The thesis

**The AI-governance market is being sold closed, per-seat, questionnaire-first platforms that cost six figures and still cannot see what actually runs. Norinth makes them unnecessary.**

Norinth is free, Apache-2.0, and runs inside the customer's own environment. It starts from runtime evidence (the SDK and OpenTelemetry, not a survey), enforces governance (release gates, separation of duties, signed evidence) rather than displaying it, and produces the audit packet auditors and regulators ask for. There is no hosted tier, no paid tier, and no vendor in the data path.

The strategy is to **undercut the Credo AI / Holistic AI / OneTrust / IBM watsonx.governance class of product on every axis a buyer cares about**:

| Buyer question | Closed governance suites | Norinth |
|---|---|---|
| What does it cost? | Six-figure annual contracts, per seat or per "use case" | $0. Your infrastructure and one part-time platform engineer. |
| Where does my data go? | Their cloud; vendor security questionnaire required | Nowhere. Runs in your VPC. Prompt/completion text never leaves by default. |
| How do they know what I run? | You fill in an intake form | The SDK / your LLM gateway / OTel tells it, including the systems nobody registered |
| Can I read the code my evidence depends on? | No | Every line, including the evidence engine and the audit chain |
| Does it enforce anything? | Dashboards and workflows | Release gates fail your pipeline; admins cannot approve; evidence must be signed by CI |
| How long to first value? | Procurement, then implementation partner | Ten minutes from a curl command |
| What if the vendor is acquired or pivots? | Your evidence is in their database | It is in your PostgreSQL |

Three-word positioning: **runtime → evidence → assurance.** The open-source move adds a fourth word: **yours.**

## 2. Who adopts it, and who champions

Same ICP as before; the open model widens the front door.

- **Health systems and medical-AI builders** (beachhead). HIPAA, FDA PCCP, Part 11, and the healthcare AI assurance/certification programs now emerging (Norinth has no affiliation with any of them; it produces the organizational evidence they ask for). Ambient documentation, imaging, agentic back-office — most of it outside the EHR vendor's governance. Health systems are especially receptive to self-hosting: no BAA negotiation with yet another vendor, no PHI-adjacent telemetry leaving the network.
- **Regulated enterprises with consequential AI**: EU AI Act high-risk (2 Dec 2027), Colorado ADMT (Jan 2027), Texas TRAIGA, NYC LL144, bank model-risk.
- **Public sector and defence-adjacent**, who cannot use SaaS governance tools at all.

**Champion:** the AI/ML platform lead who owns the runtime and hates evidence collection by spreadsheet. They can install Norinth on a Friday afternoon without asking anyone.
**Sponsor:** Chief AI / Risk / Compliance Officer, CISO, or the AI governance council, who gets an audit packet instead of a vendor contract to justify.
**Blockers, and the answer:** Security/AppSec ("is this safe to run?") — source, SBOM, signed images, threat model, hardening guide. Procurement — there is nothing to procure.

## 3. The wedge

Lead with what closed suites cannot do:

1. **Runtime inventory and shadow-AI discovery** — in minutes, from what runs.
2. **Control evidence and an AI-BOM generated from real calls** — CycloneDX, framework-mapped, gaps named.

Expand into what they sell expensively: intake and tiering, routed reviews with separation of duties, release gates with signed evidence, incidents, the audit packet.

## 4. Motion: install-led adoption

The funnel is the install command, not a sales call.

1. **Landing page → one command.** `curl … | bash` on a laptop or VM; `helm install` for Kubernetes; an OTel exporter snippet for teams already on a collector. Ten-minute promise.
2. **First-run wizard** replaces the admin console for the first five minutes: claim admin, name the organization, ingestion key, paste-ready snippet, live "first event received".
3. **`norinth doctor`** proves the path end to end; **`norinth gate check`** is the one line that puts enforcement into CI.
4. **Getting Started checklist** inside the product drives the governance rollout (reviewers, owners, signed evidence, identity provider, first audit packet).
5. **Operator docs and artifacts** — signed GHCR images, SBOM, Helm chart, backup/upgrade runbooks, threat model — are what AppSec reviews instead of a vendor questionnaire.

Metrics that matter: installs (image pulls), organizations that reach "first event", organizations that export an audit packet, GitHub stars/issues, contributors.

## 5. Competitive frame

| Camp | Their pitch | Their gap | Norinth's line |
|---|---|---|---|
| Governance suites (Credo AI, Holistic AI, OneTrust, IBM) | Policy packs, intake, reporting | Closed, costly, questionnaire-first, runtime bolted on | "You should not have to pay six figures to find out what AI you run." |
| Observability/security (Datadog, Arize, Fiddler, Prisma AIRS) | Runtime signal | No regulatory evidence, no system of record | "They tell you what happened; we turn it into evidence you own." |
| Compliance automation (Vanta, Drata) | Evidence workflows | No model/runtime/agent depth | "They file paperwork; we generate the AI evidence they can't see." |
| Healthcare-native (Qualified Health, Epic Seismometer) | Clinical validation | Narrow estate, hosted | "Whole estate, your network, your evidence." |

Build to OpenTelemetry GenAI conventions so Norinth consumes the observability layer instead of competing with it.

## 6. Enterprise readiness (what gates adoption)

| Requirement | Status |
|---|---|
| RBAC with separation of duties | Shipped |
| Tamper-evident audit log | Shipped |
| Retention and erasure | Shipped |
| Per-tenant keys, tenant isolation | Shipped |
| Content-off-by-default, keyed hashing | Shipped |
| SSO (OIDC, SAML) + SCIM | Shipped |
| Signed eval evidence for release gates | Shipped |
| PostgreSQL | Shipped |
| One-command install, first-run wizard, `norinth doctor` / `gate check` | In progress |
| Signed images, SBOM, CVE scanning, Helm chart, operator docs, threat model | Next |
| Notifications (SMTP, webhooks), review SLAs/escalation | Next |
| SOC 2 / ISO 42001 *for the project* | Not applicable in the same way — no hosted service; publish the security posture and invite audit of the code instead |

## 7. Sustainability (how Revenant Research benefits)

There is no revenue in the product and none is planned inside it. Norinth is a Revenant Research product, released as open source: it establishes the runtime-evidence standard for AI governance, builds the reputation and relationships that feed the portfolio, and can support services the community asks for (implementation help, a healthcare or EU AI Act pack built with a design partner, training) without ever gating the software. If that changes, it changes here first, in public.

## 8. Proof and content

- Regulatory-deadline content timed to catalysts: EU AI Act Dec 2027, Colorado Jan 2027, healthcare AI assurance evidence checklists.
- The ten-minute demo: install, instrument the sample app, watch the inventory, findings and AI-BOM appear, export the packet.
- Design partners: 3–5 named health systems and regulated enterprises co-developing crosswalks and packs, credited publicly.
- Publish the security posture: SECURITY.md, threat model, audit history, CI results.

## 9. Sequence

| Quarter | Engineering | Adoption |
|---|---|---|
| Now | License to Apache-2.0, landing page as project site, install script, first-run wizard, `norinth` CLI | Repo public; first installs from design partners |
| +1 | Signed releases (GHCR/PyPI), SBOM, Helm chart, operator docs, threat model | AppSec reviews pass without a vendor call; deadline content live |
| +2 | SMTP/webhooks, review SLAs, role-shaped home, AI System hub, SCIM groups | Governance committees run on it; first audit packets used in real audits |
| +3 | Policy-as-code bundles, healthcare and EU AI Act packs with design partners | Reference deployments; community contributions of crosswalks |

## 10. Risks

- **"Free" reads as "unsupported."** Answer with operator docs, release discipline, fast issue response, and named design partners.
- **AppSec stalls on supply chain.** Signed images, SBOM, scanning and a threat model are P0, not later.
- **A closed vendor forks or bundles it.** Apache-2.0 allows it; the moat is maintainer credibility and the standard, not code.
- **Sustainability.** Revenant Research funds it as core IP; services remain optional and public.
