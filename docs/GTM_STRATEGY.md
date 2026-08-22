# Norinth — Go-To-Market Strategy (2026)

*Companion to `AUDIT_AND_ROADMAP_2026.md`. This is the commercial plan; the audit/roadmap is the engineering plan. Dates and market facts are drawn from the 2026 regulatory and competitive research conducted for this project; treat specific analyst placements and vendor deal terms as directional.*

---

## 1. The one-line thesis

**Norinth is the SDK-native system of record for AI governance evidence.** It captures runtime telemetry at the source, turns it into framework-mapped control evidence and an audit-grade trail, and drives the human workflow (intake → risk → review → deployment gate → incident) on top. The wedge is that we start from **runtime truth**, not a questionnaire.

Why that matters commercially: the 2026 market splits into two camps that each have half the product.
- **Governance/workflow platforms** (Credo AI, Holistic AI, OneTrust, IBM watsonx.governance, Vanta/Drata's new AI modules) own policy packs, intake, and reporting but bolt runtime on *last* — most ship runtime "in preview" in 2026.
- **AI observability/security** tools (Datadog, Arize, Fiddler, Prisma AIRS, HiddenLayer) own the runtime signal but ship **no** regulatory policy content or evidence-of-record.

Norinth attacks from the **defensible middle**: the compliance-grade system of record that *consumes* runtime signals. The open SDK makes the runtime layer land bottom-up; the closed platform holds the moat (framework mapping, evidence integrity, the enterprise network).

---

## 2. Ideal customer profile (ICP) and beachhead

### Primary beachhead: US health systems & medical-AI builders
The least-consolidated, highest-urgency segment, with proven budget:
- **Budget exists**: Qualified Health raised a $125M Series B (Mar 2026) for exactly this problem; health systems are staffing AI governance committees now.
- **Coverage gap**: Epic's Seismometer only governs the Epic estate — ambient scribes, imaging AI, agentic back-office, and third-party GenAI are ungoverned.
- **Timed catalyst**: the **Joint Commission + CHAI "Responsible Use of AI in Healthcare" certification launched June 2026**. Health systems need *organizational* evidence (governance, monitoring, transparency) — precisely what Norinth produces. Position Norinth as "the evidence engine for RUAIH certification and CHAI model-card intake."
- **Medical-device makers** need FDA **PCCP** change-control evidence, TPLC monitoring, and 21 CFR Part 11 records — the deployment-gate + material-change + tamper-evident-audit primitives map directly.

**Entry motion**: land in one service line (e.g., radiology AI or ambient documentation) with inventory + monitoring, expand to the enterprise AI estate.

### Secondary: Fortune-500 enterprises with consequential/regulated AI
Financial services, insurance, HR/employment, and any deployer of "high-impact" or "consequential-decision" AI:
- **Timed catalysts**: EU AI Act **Art 50 transparency is live now (Aug 2026)**; the **high-risk regime lands Dec 2, 2027** (Digital Omnibus deferral) — a **~16-month runway to sell instrumentation "before the deadline."** US state laws stack up (Colorado ADMT **Jan 2027**, Texas TRAIGA live, Illinois/NYC employment-AI). Banking model-risk (SR 26-2) and NAIC insurer-AI bulletins add regulated verticals.
- **ISO/IEC 42001 is now table-stakes** for regulated AI — buyers want evidence automation against it, and want their *vendor* to be 42001-certified too.

### Who signs and who champions
- **Economic buyer**: Chief AI Officer / Chief Risk & Compliance Officer / CISO (increasingly a joint AI-governance council — IAPP reports ~77% of orgs now staff AI governance).
- **Champion**: the AI platform/ML-platform lead who owns the runtime and is tired of manual evidence collection.
- **Blockers**: Security/TPRM (answered by the trust program in §6), Legal/Privacy (answered by retention/erasure + BAA).

---

## 3. The wedge product (what we sell first)

Do **not** lead with "full AI governance suite." Lead with the two things only a runtime-native product does well:

1. **Runtime AI inventory + shadow-AI discovery.** "Point the SDK (or your LLM gateway / OTel pipeline) at your stack and get a live, evidence-backed inventory of every AI application, model, provider, workflow, and — soon — agent, including the ones nobody registered." Auto-discovery of shadow AI is the #1 ranked buyer capability in 2026.
2. **Runtime-derived AIBOM + control evidence.** A CycloneDX AI-BOM and NIST AI RMF / ISO 42001 / EU AI Act control evidence generated *from what actually ran*, not from a spreadsheet. This is a genuine differentiator — governance pure-plays' AIBOMs are thin.

These two create the "aha" in a POC and are hard for questionnaire-first competitors to match.

**Expand from there** into the workflow the platform already implements: use-case intake with risk tiering → risk register → routed review queue with **separation of duties** → deployment approval gates → incident register → the cross-tenant Enterprise Network.

---

## 4. Motion: open-core, developer-led land → enterprise expand

The repo's licensing split *is* the GTM:
- **Open SDK (Apache-2.0)** — the top of funnel. Auditable-by-design, zero-dependency, fail-open. Engineers adopt it because it's safe (observe-only, can't take down prod) and trivial to add. Distribute via PyPI, docs, and framework/gateway integrations (LiteLLM, Portkey, Kong, OpenTelemetry GenAI). **The SDK is marketing, not moat.**
- **Closed platform (commercial)** — the moat and the revenue. Framework mapping, evidence integrity (tamper-evident audit), multi-tenant RBAC, the enterprise network, reporting/audit packets.

**Funnel**: dev adds SDK in a side project or one service → inventory appears → governance/compliance team sees value → land a paid platform tenant for one team → expand to the enterprise estate and additional frameworks.

**Sales-assist** kicks in at the platform tier (regulated buyers won't self-serve a compliance system of record). Target motion: PLG-sourced pipeline, enterprise-closed contracts.

---

## 5. Positioning & competitive frame

| Competitor camp | Their strength | Their gap | Norinth's line |
|---|---|---|---|
| Governance/workflow (Credo AI, Holistic AI, OneTrust, IBM) | Policy packs, intake, reporting, brand | Runtime is bolted on last / in preview | "They start from a questionnaire; we start from what actually ran." |
| Observability/security (Datadog, Arize, Fiddler, Prisma AIRS) | Deep runtime signal | No regulatory policy content, not an evidence system of record | "They tell you what happened; we turn it into audit-ready evidence mapped to your frameworks." |
| Compliance automation (Vanta, Drata, Secureframe) | Evidence automation, SOC2/42001 workflows | No model-level/runtime/agent depth | "They automate the paperwork; we generate the underlying AI evidence they can't see." |
| Healthcare-native (Qualified Health, Ferrum, Epic Seismometer) | Clinical validation, health workflows | Narrow to clinical/imaging or Epic estate | "We govern the *whole* AI estate — clinical, administrative, and agentic — and feed your CHAI/Joint-Commission evidence." |

**Three-word positioning**: *runtime → evidence → assurance.*

Consolidation reality (2026): runtime-security and observability players are being acquired (Palo Alto/Protect AI, Check Point/Lakera, CrowdStrike/Pangea, Dynatrace/Arize, CoreWeave/W&B). The durable independent position is **not** another runtime tool — it's the **compliance/evidence system of record** that ingests everyone's signals. Build to OpenTelemetry GenAI conventions so we consume, not compete with, the observability layer.

---

## 6. Enterprise readiness = the deal-gating trust program

Regulated buyers gate on a security/compliance checklist before they'll evaluate features. This is where the audit remediation directly enables GTM. Map engineering milestones to sales unlocks:

| Buyer requirement (RFP / TPRM) | Status after hardening program | Sales unlock |
|---|---|---|
| **RBAC with separation of duties** | ✅ shipped (admin vs governance-decision planes are mutually exclusive; no self-escalation) | Answers the #1 governance-buyer objection: "can one person approve their own AI?" |
| **Tamper-evident audit log** | ✅ shipped (hash-chained, verifiable) | SOC 2 CC7.2 / HIPAA §164.312(b) / 21 CFR Part 11 evidence |
| **Data retention & right-to-erasure** | ✅ shipped (tenant purge + retention window) | GDPR Art 17 / CCPA / BAA return-or-destroy |
| **Per-tenant auth, tenant isolation** | ✅ shipped (per-tenant keys, fail-closed isolation) | Multi-tenant SaaS security review |
| **Content-off-by-default, keyed hashing** | ✅ shipped (SDK privacy hardening) | HIPAA / data-minimization; enables the "no raw PHI" claim |
| SSO (SAML/OIDC) + SCIM | ⏳ roadmap (Phase 3) | Table-stakes; blocks enterprise close until shipped |
| SOC 2 Type II | ⏳ start now | Universal procurement gate |
| ISO 42001 (vendor-certified) | ⏳ Phase 1–2 | Credibility signal — an AI-governance vendor must eat its own cooking |
| HIPAA BAA / HITRUST | ⏳ healthcare motion | Required before any PHI touches the platform |
| Postgres/HA, data residency | ⏳ Phase 1 | Architecture review (SQLite is disqualifying at scale) |

**GTM implication**: the P0 engineering items (SSO/SCIM, Postgres, SOC 2 kickoff) are not "later" — they are **pipeline unlocks**. Sequence them against the first design-partner contracts.

> The multi-tenant, delegated-administration model — **super-admin → organization → org-admin → users → scoped roles**, with enforced separation of duties and a tamper-evident trail — is itself a selling point. Enterprise buyers need delegated administration they can trust; most AI-governance point tools have shallow RBAC. Norinth's is real.

---

## 7. Pricing & packaging (hypothesis to test)

Competitor pricing is almost universally opaque ("request a demo"), which is an opportunity to be more legible.

- **Free / OSS**: the SDK, forever. Local single-tenant platform for evaluation.
- **Team** (self-serve, PLG): inventory + one framework (NIST AI RMF *or* ISO 42001), basic risk/review, N AI systems. Land here.
- **Enterprise** (sales-led): all frameworks + crosswalks, SSO/SCIM, tamper-evident audit + audit-packet export, deployment gates, incident management, RBAC/SoD, retention/legal-hold, SIEM export, HA/residency. Priced per **governed AI system** (aligns cost to value and to the inventory the SDK produces) plus platform base.
- **Network / Enterprise Subscriber**: the cross-tenant vendor-risk network (already a role tier in the platform) — a premium add-on and a data-network-effect moat.
- **Regulated add-ons**: Healthcare pack (CHAI model cards, RUAIH evidence, 21 CFR Part 11 e-signatures, HIPAA BAA); EU AI Act pack (FRIA templates, Art 12 logging retention, Art 73 incident timers).

Value metric = **governed AI systems**, because it's what the runtime inventory measures and it grows as the customer's AI estate grows (land-and-expand built in).

---

## 8. Channels & partnerships

- **Cloud marketplaces** (AWS/Azure/GCP) — procurement path for enterprise budget; note AWS Audit Manager's GenAI framework closed to new customers (whitespace).
- **GSIs / advisory** (Big 4 AI-assurance practices, boutique AI-risk firms) — they need a tooling layer under their assurance engagements.
- **Healthcare ecosystem** — CHAI (model-card registry interop), Joint Commission RUAIH readiness, health-IT/EHR integrators. Interop with Epic/FHIR and CHAI Applied Model Cards is an RFP line.
- **LLM gateways & observability** (LiteLLM, Portkey, Kong AI Gateway, OpenTelemetry) — integration partners for frictionless ingestion; meet customers where the traffic already flows.

---

## 9. Proof, content, and demand gen

- **Regulatory-deadline content** as the demand engine: "EU AI Act high-risk: what to instrument before Dec 2027," "RUAIH certification evidence checklist," "Colorado ADMT: your Jan 2027 readiness." Time content to the catalysts in §2.
- **The runtime-inventory demo** as the hero motion: a prospect installs the SDK against a sample app and watches the AIBOM + control evidence populate in minutes.
- **Open-source credibility**: the Apache SDK, a public PROTOCOL.md, and this repo's transparent audit/hardening history are trust assets — publish the security posture.
- **Design partners**: 3–5 named health systems + regulated enterprises, co-developing the framework crosswalks and healthcare pack in exchange for reference logos and case studies.

---

## 10. 4-quarter GTM sequence (paired with the engineering roadmap)

| Quarter | Engineering (from roadmap) | GTM |
|---|---|---|
| **Q1** | Finish Phase 0/1 security (done: showstoppers, RBAC/SoD, audit integrity, retention); start Postgres + SSO/SCIM; kick off SOC 2 | Sign 3–5 design partners (health + regulated enterprise); publish SDK + deadline content; PLG funnel live |
| **Q2** | SSO/SCIM + Postgres/HA GA; framework crosswalk engine (NIST AI RMF + ISO 42001 + EU AI Act); audit-packet export | First paid Team tenants; SOC 2 Type I; ISO 42001 gap assessment; marketplace listing |
| **Q3** | Healthcare pack (CHAI cards, RUAIH evidence, Part 11 e-sig); OTel GenAI ingestion; agentic governance v1 | First enterprise contracts; HIPAA BAA; health-system reference; GSI partnership |
| **Q4** | Enterprise Network GA; SIEM export; regulatory change tracking; SOC 2 Type II underway | Expand within accounts (land→estate); Network add-on; analyst briefings (Gartner AI Governance MQ, Forrester Wave) |

---

## 11. Risks & how we counter them

- **Incumbent brand & policy content** (Credo/OneTrust) → counter with runtime depth + open-source adoption + healthcare focus they underweight.
- **Observability vendors adding governance veneer** (Datadog/Arize) → counter with real regulatory crosswalks + evidence-of-record + audit integrity they don't build.
- **"Agentic project cancellation" market chill** (Gartner: >40% of agentic projects cancelled by 2027) → govern *all* AI (not just agents); position as the control that de-risks agentic adoption, not a bet on it.
- **Long enterprise sales cycles** → the open SDK + PLG Team tier shorten time-to-value and seed champions before the enterprise motion.
- **Trust-program gaps block deals** → treat SSO/SCIM/SOC 2/Postgres as pipeline unlocks, sequenced against real contracts (§6).

---

*Bottom line: the platform's defensible position is "runtime → evidence → assurance," landed by an open SDK and monetized by a closed, enterprise-grade, multi-tenant system of record. The security-hardening program isn't just risk reduction — each item (RBAC/SoD, tamper-evident audit, retention, tenant isolation, content-off-by-default) is a specific enterprise/health-system deal unlock.*
