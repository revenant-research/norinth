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
import styles from "./landing.module.css";

/**
 * Project site, structured on docs/GTM_STRATEGY.md (open source, self-hosted):
 *   §1 thesis → hero + "What you are not paying for";  §4 motion → "Get started";
 *   §2 ICP → "Built for";  §3 wedge → "Start here";  §5 → "Why Norinth";
 *   §6 → "Security";  docs;  "Get help" replaces the sales funnel.
 * Visual language follows the Revenant Research identity via src/design.
 */

const CATALYSTS = [
  { label: "EU AI Act high-risk", value: "Dec 2027", note: "obligations apply" },
  { label: "Colorado ADMT", value: "Jan 2027", note: "in force" },
  { label: "Joint Commission / CHAI", value: "Live", note: "RUAIH certification" },
  { label: "ISO/IEC 42001", value: "Table stakes", note: "for regulated AI" },
];

const AUDIENCES = [
  {
    eyebrow: "Beachhead · Health systems",
    title: "Ambient scribes, imaging models and back-office agents, most of them outside the EHR vendor's governance.",
    body: "Joint Commission and CHAI certification asks for organizational evidence: an inventory, monitoring, named accountability, and a record of decisions. Norinth produces that evidence from what actually runs, across the whole estate, not just the Epic footprint.",
    tags: ["RUAIH", "CHAI model cards", "HIPAA", "FDA PCCP", "21 CFR Part 11"],
  },
  {
    eyebrow: "Regulated enterprise",
    title: "Credit, insurance, hiring and customer-facing decisions now carry statutory obligations.",
    body: "The EU AI Act, Colorado, Texas, New York City and bank model-risk guidance all ask the same three questions: which systems do you run, who approved them, and on what evidence. Norinth answers with records, not spreadsheets.",
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
norinth.init(api_key=os.environ["NORINTH_API_KEY"], project="claims")
# OpenAI and Anthropic clients are auto-instrumented from here.`,
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
  { them: "Governance suites start from a questionnaire.", us: "We start from what actually ran." },
  { them: "Observability tools tell you what happened.", us: "We turn it into evidence mapped to your frameworks." },
  { them: "Compliance automation files the paperwork.", us: "We generate the AI evidence it cannot see." },
];

const FRAMEWORKS = ["NIST AI RMF 1.0", "ISO/IEC 42001", "EU AI Act", "OWASP LLM Top 10", "OWASP Agentic", "HIPAA", "SOC 2", "CHAI / RUAIH"];

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

const UNDERCUT = [
  { q: "What does it cost?", them: "Six-figure annual contracts, per seat or per use case.", us: "Nothing. Your infrastructure and a part-time platform engineer." },
  { q: "Where does my data go?", them: "Their cloud, after a vendor security questionnaire.", us: "Nowhere. It runs in your network; prompt text never leaves by default." },
  { q: "How does it know what I run?", them: "You fill in an intake form.", us: "Your SDK, gateway or OpenTelemetry pipeline tells it, including the systems nobody registered." },
  { q: "Can I read the code my evidence depends on?", them: "No.", us: "Every line, including the evidence engine and the audit chain." },
  { q: "Does it enforce anything?", them: "Dashboards and workflows.", us: "Release gates fail your pipeline; admins cannot approve; evidence must be signed by CI." },
  { q: "What if the vendor pivots or is acquired?", them: "Your evidence is in their database.", us: "It is in your PostgreSQL." },
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

export function LandingPage({ onClientSignIn, onAdminSignIn }: { onClientSignIn: () => void; onAdminSignIn: () => void }) {
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

      <Container>
        <div className={styles.hero}>
          <Eyebrow>Open source · Apache-2.0 · Runs in your network</Eyebrow>
          <Heading level={1}>AI governance you can install in ten minutes and never pay for.</Heading>
          <Lede>
            Norinth turns the telemetry your AI applications already produce into a live inventory, routes reviews to
            named owners, blocks releases that lack evidence, and produces the audit packet your auditor, regulator and
            board ask for. Free, open source, self-hosted. The closed governance suites become unnecessary.
          </Lede>
          <div className={styles.actions}>
            <ButtonLink size="lg" href="#start">Install it</ButtonLink>
            <ButtonLink variant="link" href="https://github.com/revenant-research/norinth">Read the source on GitHub</ButtonLink>
          </div>
          <ul className={styles.proof} aria-label="Key facts">
            <li>No hosted tier, no paid tier, no vendor in the data path</li>
            <li>Evidence from what ran, not a questionnaire</li>
            <li>Release gates need a named human and CI-signed evidence</li>
          </ul>
        </div>

        <StatGroup columns={4}>
          {CATALYSTS.map((c) => (
            <Stat key={c.label} label={c.label} value={c.value} note={c.note} />
          ))}
        </StatGroup>

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
            Requirements: Docker (the installer can install it on Ubuntu LTS), 2 CPU, 4 GB RAM, PostgreSQL for production. Python 3.11+ for the SDK.
          </Text>
        </Section>

        <Section id="undercut" eyebrow="What you are not paying for" title="The questions you would ask a governance vendor, answered.">
          <div className={styles.compare} role="table" aria-label="Closed governance suites compared with Norinth">
            <div className={styles.compareHead} role="row">
              <span role="columnheader">Question</span>
              <span role="columnheader">Closed governance suites</span>
              <span role="columnheader">Norinth</span>
            </div>
            {UNDERCUT.map((row) => (
              <div className={styles.compareRow} role="row" key={row.q}>
                <strong role="cell">{row.q}</strong>
                <Text size="sm" role="cell">{row.them}</Text>
                <Text size="sm" tone="ink" role="cell">{row.us}</Text>
              </div>
            ))}
          </div>
        </Section>

        <Section id="who" eyebrow="Who it is for" title="Built for teams that answer to regulators.">
          <Grid min="320px" gap={4}>
            {AUDIENCES.map((a) => (
              <Card key={a.eyebrow} as="article" padding="lg">
                <Eyebrow>{a.eyebrow}</Eyebrow>
                <Heading level={3}>{a.title}</Heading>
                <Text>{a.body}</Text>
                <ul className={styles.tagRow} aria-label="Relevant frameworks">
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
            {WEDGE.map((w) => (
              <Card key={w.eyebrow} as="article" padding="lg" tone="lead">
                <Eyebrow>{w.eyebrow}</Eyebrow>
                <Heading level={3}>{w.title}</Heading>
                <Text>{w.body}</Text>
              </Card>
            ))}
          </Grid>
        </Section>

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

        <Section id="capabilities" eyebrow="The platform" title="Governance as enforcement, not a dashboard.">
          <Grid min="280px" gap={4}>
            {CAPABILITIES.map((c) => (
              <Card key={c.title} as="article">
                <Heading level={3} size="lg">{c.title}</Heading>
                <Text size="sm">{c.body}</Text>
              </Card>
            ))}
          </Grid>
          <div className={styles.frameworks} aria-label="Frameworks covered">
            {FRAMEWORKS.map((f) => (
              <Chip key={f}>{f}</Chip>
            ))}
          </div>
        </Section>
      </Container>

      <div className={styles.band}>
        <Container>
          <Stack gap={5}>
            <Eyebrow>Why Norinth</Eyebrow>
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
      </div>

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

        <ContactSection />
      </Container>

      <footer className={styles.footer}>
        <div className={styles.brand}>
          <span className={styles.brandName}>Norinth</span>
          <span className={styles.brandBy}>A Revenant Research company</span>
          <Text size="sm">Open-source AI governance from runtime evidence. Apache-2.0.</Text>
        </div>
        <div className={styles.footerLinks}>
          <ButtonLink variant="link" href="https://github.com/revenant-research/norinth">GitHub</ButtonLink>
          <ButtonLink variant="link" href="https://github.com/revenant-research/norinth/blob/main/LICENSE">Apache-2.0</ButtonLink>
          <ButtonLink variant="link" href="https://www.revenantresearch.com/">revenantresearch.com</ButtonLink>
          <Button variant="secondary" size="sm" onClick={onClientSignIn}>Sign in</Button>
          <Button variant="link" size="sm" onClick={onAdminSignIn}>Platform administrator access</Button>
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
      title="Talk to the maintainers."
      lede="Stuck on an install, reviewing it for your security team, or want to be a design partner for a healthcare or EU AI Act pack? Tell us what you run. Bugs and feature requests belong on GitHub issues; everything else here."
    >
      {state === "sent" ? (
        <Callout tone="success" title="Thanks.">We have your message and will reply within a few business days.</Callout>
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
                  { value: "demo", label: "Become a design partner" },
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
