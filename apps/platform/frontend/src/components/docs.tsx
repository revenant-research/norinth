import { ButtonLink, Code, Inline, Stack, Table, Text } from "../design";
import { Section } from "./ui";

/**
 * In-product reference. Short, plain-language explanations of the model the
 * product enforces, so a new administrator or reviewer does not have to leave
 * the app to understand what a role, a gate, or a finding means.
 */

const ROLES: Array<{ role: string; does: string; cannot: string }> = [
  { role: "org_admin", does: "Manages users, roles, identity, keys and policies for the organization.", cannot: "Approve reviews or release gates, accept risks, or change their own roles." },
  { role: "governance_admin", does: "Decides reviews and release gates, accepts or mitigates risks, creates exceptions.", cannot: "Manage users or integrations; approve work they submitted." },
  { role: "risk_owner", does: "Accepts, mitigates or closes risk findings; owns exceptions.", cannot: "Approve release gates or manage the organization." },
  { role: "control_owner", does: "Attests control evidence and waives controls with a rationale.", cannot: "Accept risks or approve releases." },
  { role: "governance_reviewer", does: "Records review decisions on tasks routed to their role.", cannot: "Approve gates, manage people, or review their own submissions." },
  { role: "owner_admin", does: "Names accountable business and technical owners for systems.", cannot: "Make governance decisions." },
];

const GLOSSARY: Array<{ term: string; body: string }> = [
  { term: "AI system (application)", body: "Anything that calls a model: a service, a workflow, an agent. Discovered from telemetry or registered through Intake. Carries a risk tier, named owners, and a lifecycle stage." },
  { term: "Shadow AI", body: "A system, model, provider or agent that appears in telemetry but was never registered. It is flagged as a finding until someone claims it." },
  { term: "Risk finding", body: "A rule-generated or human-raised issue with a severity, an owner and a status (open, accepted, mitigated, closed). Accepted risks need an exception with an expiry." },
  { term: "Control evidence", body: "A control from a framework (NIST AI RMF, ISO 42001, EU AI Act, OWASP) assessed as passing or missing based on what the telemetry shows actually happened." },
  { term: "Review task", body: "Work routed to a role with a due date: intake review, risk review, control review, change review. A person who originated the work cannot decide it." },
  { term: "Release gate", body: "Created for every deployment version. Approved only by a named reviewer, with a linked prompt version and a passing evaluation. Never approved automatically." },
  { term: "Attested evidence", body: "An evaluation result signed by your CI pipeline's key. Once a key is registered, unsigned evals no longer satisfy release gates." },
  { term: "Separation of duties", body: "Administration and decision authority are held by different people. Nobody approves their own work, grants their own roles, or approves their own release." },
  { term: "Audit packet", body: "A single export an auditor can read: inventory, AI-BOM, framework coverage and evidence, decisions with rationale, exceptions, gates, incidents, and a verified audit trail." },
];

const INTEGRATIONS: Array<{ name: string; body: string }> = [
  { name: "Python SDK", body: "pip install norinth-logger. Auto-instruments OpenAI and Anthropic clients (sync and async). Fail-open, privacy-safe by default, Apache-2.0." },
  { name: "OpenTelemetry", body: "POST GenAI semantic-convention spans to /v1/otel/traces with your ingestion key. Works with any collector or LLM gateway that emits OTel." },
  { name: "CI evidence signing", body: "python -m norinth_logger.attest keygen; sign eval results with sign_eval_result(). Register the public key under Identity & Integrations." },
  { name: "Identity", body: "OpenID Connect (PKCE), SAML 2.0, and SCIM 2.0 provisioning with immediate deprovisioning. Configure under Identity & Integrations." },
  { name: "API", body: "Everything in the product is an authenticated JSON API with pagination. The OpenAPI reference is at /docs on this server." },
];

export function DocsView() {
  return (
    <>
      <Section title="Roles and who can do what" description="Authorization is by permission, not by page. These are the default role grants; org admins can adjust permissions under People & Access.">
        <Table columns={[{ key: "role", label: "Role", width: "22%" }, { key: "can", label: "Can" }, { key: "cannot", label: "Cannot" }]}>
          {ROLES.map((r) => (
            <tr key={r.role}>
              <td><Code>{r.role}</Code></td>
              <td>{r.does}</td>
              <td>{r.cannot}</td>
            </tr>
          ))}
        </Table>
      </Section>
      <Section title="Terms used in the product">
        <Stack as="dl" gap={3} style={{ margin: 0 }}>
          {GLOSSARY.map((g) => (
            <div key={g.term}>
              <Text as="dt" tone="ink" size="md" style={{ fontWeight: 600 }}>{g.term}</Text>
              <Text as="dd" size="sm" style={{ marginLeft: 0 }}>{g.body}</Text>
            </div>
          ))}
        </Stack>
      </Section>
      <Section title="Integrations">
        <Stack as="dl" gap={3} style={{ margin: 0 }}>
          {INTEGRATIONS.map((g) => (
            <div key={g.name}>
              <Text as="dt" tone="ink" size="md" style={{ fontWeight: 600 }}>{g.name}</Text>
              <Text as="dd" size="sm" style={{ marginLeft: 0 }}>{g.body}</Text>
            </div>
          ))}
        </Stack>
        <Inline gap={4}>
          <ButtonLink variant="link" size="sm" href="/docs" target="_blank" rel="noreferrer">Open the API reference</ButtonLink>
          <ButtonLink variant="link" size="sm" href="https://github.com/revenant-research/norinth/tree/main/packages/python-sdk#readme" target="_blank" rel="noreferrer">SDK guide</ButtonLink>
        </Inline>
      </Section>
    </>
  );
}
