import { useState } from "react";

import { postJson } from "../api";
import {
  Button,
  ButtonLink,
  Callout,
  Card,
  Chip,
  CodeBlock,
  Container,
  Eyebrow,
  FormGrid,
  Grid,
  Heading,
  Lede,
  SelectField,
  Stack,
  Stat,
  StatGroup,
  Text,
  TextArea,
  TextField,
} from "../design";
import { ChromeBand, ChromeStrip, Screenshot } from "./Showcase";
import styles from "./landing.module.css";

// project site: what it is, who it's for, how to install, why it's built this
// way, security. "get help" links to github, not a sales funnel

// dated regulatory facts only, each with a primary source
const CATALYSTS = [
  { label: "EU AI Act · Annex III high-risk obligations", value: "2 Dec 2027", note: "Regulation (EU) 2026/1744", href: "https://www.aiactblog.nl/en/posts/digital-omnibus-high-risk-postponement-december-2027" },
  { label: "Colorado automated decision-making law", value: "1 Jan 2027", note: "SB 26-189", href: "https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/colorado-postpones-implementation-of-colorado-ai-act-sb-24-205" },
  { label: "Joint Commission AI certification (voluntary)", value: "Live", note: "launched 1 Jun 2026", href: "https://www.jointcommission.org/en-us/knowledge-library/news/2026-05-responsible-use-of-ai-in-healthcare-certification" },
];

const AUDIENCES = [
  {
    eyebrow: "Health systems",
    title: "Ambient scribes, imaging models and back-office agents across the whole estate.",
    body: "Healthcare AI assurance programs ask for organizational evidence: an inventory, monitoring, named accountability, decisions on record. Norinth produces it from what actually runs.",
    tags: ["HIPAA", "FDA PCCP", "21 CFR Part 11", "ISO/IEC 42001"],
  },
  {
    eyebrow: "Regulated enterprise",
    title: "Credit, insurance, hiring and customer-facing decisions now carry statutory obligations.",
    body: "The EU AI Act, Colorado, Texas, New York City and bank model-risk guidance ask the same three questions: which systems do you run, who approved them, on what evidence. Norinth answers with records.",
    tags: ["EU AI Act", "NIST AI RMF", "ISO/IEC 42001", "Colorado ADMT", "SR 11-7"],
  },
];

const WEDGE = [
  {
    eyebrow: "Wedge · Inventory",
    title: "A live inventory, including the AI nobody registered.",
    body: "Point the SDK, your LLM gateway or your OpenTelemetry pipeline at Norinth. Every application, model, provider, workflow and agent appears within minutes, with unregistered ones flagged as shadow AI.",
  },
  {
    eyebrow: "Wedge · Evidence",
    title: "Control evidence and an AI-BOM generated from what ran.",
    body: "A CycloneDX AI-BOM and framework-mapped control evidence built from real calls, guardrail decisions and evaluation results. Coverage per framework, with every gap named.",
  },
];

const STEPS = [
  {
    title: "Instrument",
    body: "Ten lines in your service. The SDK is fail-open and observe-only: it cannot take production down, and it hashes prompts and completions instead of sending them.",
    code: `pip install norinth-logger

import norinth_logger as norinth
from openai import OpenAI
norinth.init(api_key=os.environ["NORINTH_API_KEY"], project="claims")
client = norinth.wrap(OpenAI())  # records each model call it makes`,
  },
  {
    title: "Govern",
    body: "Tier each system, name accountable owners, route reviews to the right role. Releases wait on a gate that needs a linked prompt version, a signed passing eval, and a reviewer who did not submit the change.",
  },
  {
    title: "Prove",
    body: "Export the audit packet: inventory, AI-BOM, control evidence per framework, every decision with its rationale, and a hash-chained audit trail your auditor can verify.",
  },
];

const CAPABILITIES = [
  { title: "Release gates that need a human and evidence", body: "Never auto-approved. A named reviewer, a linked prompt version and a passing evaluation signed by your CI key." },
  { title: "Separation of duties, enforced", body: "Administrators cannot hold decision roles. Nobody approves their own work or changes their own permissions." },
  { title: "Agentic AI under control", body: "Register agents with an autonomy level and tool allow-list. Unregistered agents and the private-data / untrusted-input / external-action trifecta become findings." },
  { title: "Incidents with a closure record", body: "Reported by guardrails, evals or people. Closed only with a root cause, impact and remediation on file." },
  { title: "Exceptions that expire", body: "Accepting a risk needs an owner, a compensating control and an expiry date. It comes back for review when it lapses." },
  { title: "An audit trail that survives an audit", body: "Hash-chained, verifiable, exportable. Retention and erasure controls for GDPR, HIPAA and BAA return-or-destroy." },
];

const POSITIONING = [
  { them: "Questionnaires describe what people believe is running.", us: "Norinth starts from what actually ran." },
  { them: "Telemetry on its own is not evidence.", us: "Norinth maps it to the controls your frameworks name." },
  { them: "Paperwork without runtime data is hard to defend.", us: "Norinth produces the runtime evidence behind the paperwork." },
];

// only frameworks the control library actually maps controls to; a chip here
// without a matching control in governance_policy.py claims coverage we don't have
const FRAMEWORKS = ["NIST AI RMF", "ISO/IEC 42001", "EU AI Act", "SOC 2"];

const GET_STARTED = [
  {
    eyebrow: "Laptop or one VM",
    title: "One command",
    body: "Generates every secret, starts PostgreSQL and the platform, waits for /health, and prints the URL and your administrator login. The first visit opens the setup wizard.",
    code: "curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash",
  },
  {
    eyebrow: "Kubernetes",
    title: "Helm",
    body: "Signed image from GHCR, external PostgreSQL or the bundled subchart, ingress and secrets from a values file the installer can write for you.",
    code: "helm install norinth oci://ghcr.io/revenant-research/charts/norinth \\\n  --set postgres.url=$DATABASE_URL",
  },
  {
    eyebrow: "Already on OpenTelemetry",
    title: "Point your collector at it",
    body: "GenAI semantic-convention spans are accepted as-is from any collector or LLM gateway. No application code changes.",
    code: "exporters:\n  otlphttp/norinth:\n    endpoint: https://norinth.internal/v1/otel\n    headers:\n      Authorization: \"Bearer $NORINTH_API_KEY\"",
  },
];

const ANSWERS = [
  { q: "What does it cost?", us: "Nothing. Apache-2.0. You run it on your own infrastructure." },
  { q: "Where does my data go?", us: "Nowhere. It runs in your network. Prompt and completion text are hashed, not sent, unless you turn capture on." },
  { q: "How does it know what I run?", us: "Your SDK, LLM gateway or OpenTelemetry pipeline tells it, including systems nobody registered." },
  { q: "Can I read the code my evidence depends on?", us: "Every line, including the evidence engine and the hash-chained audit log." },
  { q: "Does it enforce anything?", us: "Release gates fail your pipeline; administrators cannot approve; evidence must be signed by your CI key." },
  { q: "What if the project changes direction?", us: "Your evidence is in your PostgreSQL, under a license that lets you keep running and modifying it." },
];

function Section({ id, eyebrow, title, lede, children }: { id: string; eyebrow: string; title: string; lede?: string; children: React.ReactNode }) {
  return (
    <section className={styles.section} id={id} aria-labelledby={`${id}-title`}>
      <div className={styles.sectionHead}>
        <Eyebrow>{eyebrow}</Eyebrow>
        <Heading level={2} id={`${id}-title`}>{title}</Heading>
        {lede ? <Lede>{lede}</Lede> : null}
      </div>
      {children}
    </section>
  );
}

export function LandingPage({ onClientSignIn }: { onClientSignIn: () => void }) {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div className={styles.brand}>
          <span className={styles.brandName}>Norinth</span>
          <span className={styles.brandBy}>Revenant Research</span>
        </div>
        <nav aria-label="Landing" className={styles.nav}>
          <a href="#start">Get started</a>
          <a href="#how">How it works</a>
          <a href="#capabilities">Platform</a>
          <a href="#trust">Security</a>
          <a href="#docs">Docs</a>
          <a href="https://github.com/revenant-research/norinth">GitHub</a>
        </nav>
        <div className={styles.actions}>
          <Button variant="secondary" size="sm" onClick={onClientSignIn}>Sign in</Button>
          <ButtonLink size="sm" href="#start">Install</ButtonLink>
        </div>
      </header>

      <ChromeBand streak={2} className={styles.heroBand}>
        <Container>
        <div className={styles.hero}>
          <Eyebrow tone="inverse">Open source · Apache-2.0 · Runs in your network</Eyebrow>
          <Heading level={1}>AI governance you can install in ten minutes and never pay for.</Heading>
          <Lede>
            A live inventory from the telemetry you already produce. Reviews routed to named owners. Releases blocked
            without evidence. The audit packet your auditor asks for. Free, open source, in your network.
          </Lede>
          <div className={styles.actions}>
            <ButtonLink size="lg" href="#start" className={styles.heroCta}>Install it</ButtonLink>
            <ButtonLink variant="secondary" size="lg" href="https://github.com/revenant-research/norinth" className={styles.heroGhost}>Read the source</ButtonLink>
          </div>
          <ul className={styles.proof} aria-label="Key facts">
            <li>No hosted tier, no paid tier, no vendor in the data path</li>
            <li>Evidence from what ran, not a questionnaire</li>
            <li>Release gates need a named human and CI-signed evidence</li>
          </ul>
        </div>

        <div className={styles.heroShot}>
        <Screenshot
          src="/assets/screens/deployments.jpg"
          alt="Norinth Deployments view: a Claims Copilot release gate in pending review, listing three open risk findings, seven missing controls, two material changes and a missing linked prompt version"
          caption="A release gate, blocked: the reviewer sees exactly what is missing before anything ships."
          priority
        />
        </div>
        </Container>
      </ChromeBand>

      <Container>
        <div className={styles.catalysts}>
        <StatGroup columns={3}>
          {CATALYSTS.map((c) => (
            <Stat key={c.label} label={c.label} value={c.value} note={<a href={c.href} target="_blank" rel="noreferrer">{c.note} ↗</a>} />
          ))}
        </StatGroup>
        </div>

        <Section id="start" eyebrow="Get started" title="Ten minutes, three ways in." lede="Pick the path that matches where you are. Each ends in the same place: the setup wizard, your first ingestion key, and the first AI system appearing in the inventory.">
          <Grid min="300px" gap={4}>
            {GET_STARTED.map((g) => (
              <Card key={g.title} as="article" padding="lg">
                <Eyebrow>{g.eyebrow}</Eyebrow>
                <Heading level={3}>{g.title}</Heading>
                <Text size="sm">{g.body}</Text>
                <CodeBlock label={`${g.title} command`}>{g.code}</CodeBlock>
              </Card>
            ))}
          </Grid>
          <Text size="sm">
            Requirements: Docker (the installer can install it on Ubuntu or Debian), PostgreSQL for production, Python 3.11+ where the SDK runs.
          </Text>
        </Section>

        <Section id="answers" eyebrow="Straight answers" title="The questions you would ask a governance vendor.">
          <div className={styles.compare} role="table" aria-label="Questions and answers about Norinth">
            <div className={styles.compareHead} role="row">
              <span role="columnheader">Question</span>
              <span role="columnheader">Norinth</span>
            </div>
            {ANSWERS.map((row) => (
              <div className={styles.compareRow} role="row" key={row.q}>
                <strong role="cell">{row.q}</strong>
                <Text size="sm" tone="ink" role="cell">{row.us}</Text>
              </div>
            ))}
          </div>
        </Section>

      </Container>
      <div className={styles.paperBand}>
      <Container>
        <Section id="who" eyebrow="Who it is for" title="Built for teams that answer to regulators.">
          <Grid min="320px" gap={4}>
            {AUDIENCES.map((a, i) => (
              <Card key={a.eyebrow} as="article" padding="md">
                <ChromeStrip streak={i === 0 ? 3 : 4} label={a.eyebrow} />
                <Heading level={3}>{a.title}</Heading>
                <Text>{a.body}</Text>
                <ul className={styles.tagRow} aria-label="Regulations these teams answer to">
                  {a.tags.map((t) => (
                    <li key={t}><Chip>{t}</Chip></li>
                  ))}
                </ul>
              </Card>
            ))}
          </Grid>
        </Section>

        <Section id="wedge" eyebrow="Start here" title="Two things only a runtime-native product does well." lede="Land with the inventory and the evidence. Expand into intake, review routing, release gates and incidents once the estate is visible.">
          <Grid min="320px" gap={4}>
            {WEDGE.map((w, i) => (
              <Card key={w.eyebrow} as="article" padding="md" tone="lead">
                <ChromeStrip streak={i === 0 ? 1 : 2} label={w.eyebrow} />
                <Heading level={3}>{w.title}</Heading>
                <Text>{w.body}</Text>
              </Card>
            ))}
          </Grid>
        </Section>

      </Container>
      </div>
      <Container>
        <Section id="how" eyebrow="How it works" title="Three steps from first event to audit packet.">
          <Grid min="260px" gap={5}>
            {STEPS.map((s, i) => (
              <Card key={s.title} as="article" className={styles.step}>
                <span className={styles.stepNumber} aria-hidden="true">{i + 1}</span>
                <Heading level={3}>{s.title}</Heading>
                <Text>{s.body}</Text>
                {s.code ? <CodeBlock label={`${s.title} example`}>{s.code}</CodeBlock> : null}
              </Card>
            ))}
          </Grid>
        </Section>

      </Container>

      <ChromeBand streak={1}>
        <Container>
          <Stack gap={5}>
            <div className={styles.sectionHead}>
              <Eyebrow tone="inverse">See it</Eyebrow>
              <Heading level={2}>From first event to audit packet, on screen.</Heading>
            </div>
            <Grid min="440px" gap={5}>
              <Screenshot src="/assets/screens/inventory.jpg" alt="Inventory view listing AI systems, workflows, models and providers discovered from telemetry" caption="Inventory: every system seen in production, registered or not." />
              <Screenshot src="/assets/screens/compliance.jpg" alt="Compliance view showing framework coverage bars per framework and the audit packet export" caption="Compliance: coverage per framework, gaps named, packet export." />
              <Screenshot src="/assets/screens/agents.jpg" alt="Agents view showing registered agents with autonomy level, tool allow-list and posture findings" caption="Agents: autonomy, tool allow-lists, off-policy use as findings." />
              <Screenshot src="/assets/screens/guide.jpg" alt="Getting started checklist showing completed and pending setup steps for an organization" caption="Getting started: a checklist computed from your real state." />
            </Grid>
          </Stack>
        </Container>
      </ChromeBand>

      <Container>
        <Section id="capabilities" eyebrow="The platform" title="Governance as enforcement, not a dashboard.">
          <Grid min="280px" gap={4}>
            {CAPABILITIES.map((c) => (
              <Card key={c.title} as="article">
                <Heading level={3} size="lg">{c.title}</Heading>
                <Text size="sm">{c.body}</Text>
              </Card>
            ))}
          </Grid>
          <div className={styles.frameworks} aria-label="Frameworks the control library maps">
            {FRAMEWORKS.map((f) => (
              <Chip key={f}>{f}</Chip>
            ))}
          </div>
          <Text size="sm">The control library ships mappings for these frameworks; coverage is measured against the requirements Norinth maps, not the full regulation.</Text>
        </Section>
      </Container>

      <ChromeBand streak={2}>
        <Container>
          <Stack gap={5}>
            <Eyebrow tone="inverse">Why Norinth</Eyebrow>
            <div className={styles.quoteRow}>
              {POSITIONING.map((p) => (
                <div className={styles.quote} key={p.them}>
                  <Text size="sm">{p.them}</Text>
                  <strong>{p.us}</strong>
                </div>
              ))}
            </div>
            <Text size="sm">
              Built on OpenTelemetry GenAI conventions, so Norinth consumes your observability layer instead of competing with it.
            </Text>
          </Stack>
        </Container>
      </ChromeBand>

      <div className={styles.paperBand}>
      <Container>
        <Section id="trust" eyebrow="Security" title="The trust program is the product." lede="Your AppSec team reviews source, SBOM and CI instead of a vendor questionnaire. Every control below is shipped and verified in CI.">
          <Grid min="300px" gap={4}>
            <Card as="article">
              <Heading level={3} size="lg">Your data</Heading>
              <Text size="sm">
                The SDK sends metadata: model, provider, latency, token counts, guardrail decisions, eval results. Prompt and completion text are hashed with an organization-specific key unless you explicitly turn capture on. Each organization has its own ingestion keys; telemetry can never be attributed to another tenant.
              </Text>
            </Card>
            <Card as="article">
              <Heading level={3} size="lg">The platform</Heading>
              <Text size="sm">
                Hash-chained audit log with an integrity check, AES-256-GCM encryption of integration secrets, login throttling, CSRF protection, OpenID Connect and SAML 2.0 with SCIM deprovisioning, retention and erasure, PostgreSQL in production. The SDK is Apache-2.0 and auditable line by line.
              </Text>
              <div>
                <ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/SECURITY.md">Security policy and disclosure</ButtonLink>
              </div>
            </Card>
          </Grid>
        </Section>

        <Section id="docs" eyebrow="Documentation" title="Read it before you run it.">
          <Grid min="240px" gap={4}>
            <Card as="article">
              <Heading level={3} size="lg">Operations</Heading>
              <Text size="sm">Deploy with Docker Compose or Helm, configure every NORINTH_* variable, back up and restore PostgreSQL, upgrade with versioned migrations.</Text>
              <div><ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/docs/operations.md">Operations guide</ButtonLink></div>
            </Card>
            <Card as="article">
              <Heading level={3} size="lg">SDK quickstart</Heading>
              <Text size="sm">Install, initialize, and see your first AI system appear. Auto-instrumentation for OpenAI and Anthropic; explicit events for prompts, deployments, evals, incidents and agent runs.</Text>
              <div><ButtonLink variant="link" href="https://github.com/revenant-research/norinth/tree/main/packages/python-sdk#readme">SDK guide</ButtonLink></div>
            </Card>
            <Card as="article">
              <Heading level={3} size="lg">Platform guide</Heading>
              <Text size="sm">Roles and separation of duties, intake and risk tiering, review routing, release gates and signed evidence, incidents, and the audit packet.</Text>
              <div><ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/apps/platform/README.md">Platform guide</ButtonLink></div>
            </Card>
            <Card as="article">
              <Heading level={3} size="lg">API reference</Heading>
              <Text size="sm">Every platform capability is an authenticated JSON API. The OpenAPI reference is served by the platform itself.</Text>
              <div><ButtonLink variant="link" href="/docs">API reference</ButtonLink></div>
            </Card>
          </Grid>
        </Section>

      </Container>
      </div>
      <Container>
        <ContactSection />
      </Container>

      <footer className={styles.footer}>
        <div className={styles.brand}>
          <span className={styles.brandName}>Norinth</span>
          <span className={styles.brandBy}>A Revenant Research product</span>
          <Text size="sm">Open-source AI governance from runtime evidence. Apache-2.0.</Text>
        </div>
        <div className={styles.footerLinks}>
          <ButtonLink variant="link" href="https://github.com/revenant-research/norinth">GitHub</ButtonLink>
          <ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/LICENSE">Apache-2.0</ButtonLink>
          <ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/SECURITY.md">Security</ButtonLink>
          <ButtonLink variant="link" href="https://www.revenantresearch.com/">revenantresearch.com</ButtonLink>
        </div>
      </footer>
    </div>
  );
}

export function ContactSection() {
  const [form, setForm] = useState({ name: "", email: "", organization: "", interest: "pilot", message: "" });
  const [state, setState] = useState<"idle" | "busy" | "sent" | "error">("idle");
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setState("busy");
    setError("");
    try {
      await postJson("/api/public/leads", form);
      setState("sent");
    } catch (caught) {
      setState("error");
      setError(caught instanceof Error ? caught.message : "Could not send. Please try again.");
    }
  }

  return (
    <Section
      id="contact"
      eyebrow="Get help"
      title="Leave a note for this instance's administrators."
      lede="This form is served by the Norinth instance you are viewing, so your note is stored in its own admin console — not sent to the Norinth project. To reach the maintainers, open a GitHub issue or discussion; use this to contact whoever operates this deployment."
    >
      {state === "sent" ? (
        <Callout tone="success" title="Thanks.">Your note was recorded in this instance's admin console.</Callout>
      ) : (
        <form className={styles.contactForm} onSubmit={submit} aria-label="Contact">
          <Stack gap={4}>
            <FormGrid>
              <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required autoComplete="name" />
              <TextField label="Work email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required autoComplete="email" />
              <TextField label="Organization" value={form.organization} onChange={(e) => setForm({ ...form, organization: e.target.value })} required autoComplete="organization" />
              <SelectField
                label="I want to"
                value={form.interest}
                onChange={(e) => setForm({ ...form, interest: e.target.value })}
                options={[
                  { value: "pilot", label: "Get help with a deployment" },
                  { value: "demo", label: "Help shape a healthcare or EU AI Act pack" },
                  { value: "pricing", label: "Ask about implementation services" },
                  { value: "security", label: "Security review questions" },
                ]}
              />
            </FormGrid>
            <TextArea
              label="What are you running today?"
              value={form.message}
              onChange={(e) => setForm({ ...form, message: e.target.value })}
              rows={3}
              placeholder="e.g. ambient documentation in two clinics, a claims triage agent, OpenAI + Anthropic via LiteLLM"
            />
            {state === "error" ? <Callout tone="danger">{error}</Callout> : null}
            <div>
              <Button type="submit" size="lg" disabled={state === "busy"}>{state === "busy" ? "Sending" : "Send"}</Button>
            </div>
          </Stack>
        </form>
      )}
    </Section>
  );
}
