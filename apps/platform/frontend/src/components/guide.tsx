import { getJson } from "../api";
import { Badge, ButtonLink, Callout, Card, Chip, CodeBlock, Code, Heading, Inline, Stack, Text } from "../design";
import { Section, SkeletonCards } from "./ui";
import { useResource } from "./useResource";

type Step = {
  id: string;
  title: string;
  why: string;
  done: boolean;
  detail: string;
  route: string;
  action: string;
  optional?: boolean;
};

type Onboarding = {
  steps: Step[];
  completed: number;
  required: number;
  complete: boolean;
  ingestion_key_hint: string | null;
};

const SDK_SNIPPET = `pip install norinth-logger

# app startup
import os
import norinth_logger as norinth

norinth.init(
    api_key=os.environ["NORINTH_API_KEY"],      # the ingestion key you created
    endpoint=os.environ.get("NORINTH_ENDPOINT", "${window.location.origin}"),
    project="claims",                           # any grouping you like
    environment="prod",
    service="claims-api",
    application_name="Claims Copilot",          # how it appears in your inventory
)

# records every call your OpenAI and Anthropic clients make
norinth.autoinstrument()`;

const OTEL_SNIPPET = `# OpenTelemetry GenAI semantic conventions are accepted as-is.
exporters:
  otlphttp/norinth:
    traces_endpoint: ${window.location.origin}/v1/otel/traces
    headers:
      Authorization: "Bearer $NORINTH_API_KEY"`;

// getting-started checklist computed from the org's actual state (keys, events,
// systems, roles, owners, evidence, identity, packets); each step links to where
// it's done
export function GettingStarted() {
  const { value, error } = useResource(() => getJson<Onboarding>("/api/onboarding"));

  return (
    <>
      <Section
        title={value?.complete ? "Your organization is set up" : "Set up your organization"}
        description={
          value
            ? `${value.completed} of ${value.required} required steps done. Recommended steps are marked; they are what an auditor will ask about next.`
            : "Each step below is checked against your organization's real state."
        }
      >
        {error ? <Callout tone="danger">{error}</Callout> : null}
        {!value && !error ? <SkeletonCards count={4} /> : null}
        {value ? (
          <Stack as="ol" gap={3} aria-label="Setup steps" style={{ listStyle: "none", margin: 0, padding: 0 }}>
            {value.steps.map((step, index) => (
              <Card as="li" key={step.id} padding="sm" tone={step.done ? "well" : "paper"}>
                <Inline gap={3} align="start">
                  <Badge tone={step.done ? "success" : "neutral"}>{step.done ? "Done" : `Step ${index + 1}`}</Badge>
                  <Stack gap={1} style={{ flex: 1 }}>
                    <Inline gap={2} align="baseline">
                      <Heading level={3} size="lg">{step.title}</Heading>
                      {step.optional ? <Chip>Recommended</Chip> : null}
                      <Text size="sm">{step.detail}</Text>
                    </Inline>
                    <Text size="sm">{step.why}</Text>
                    {!step.done ? (
                      <div>
                        <ButtonLink variant="link" size="sm" href={`#${step.route}`}>{step.action} →</ButtonLink>
                      </div>
                    ) : null}
                  </Stack>
                </Inline>
              </Card>
            ))}
          </Stack>
        ) : null}
      </Section>

      <Section
        title="Instrument an application"
        description="Ten lines in your service. The SDK is fail-open: if Norinth is unreachable your application keeps running and nothing is lost from the request path."
      >
        <CodeBlock label="SDK setup">{SDK_SNIPPET}</CodeBlock>
        <Text size="sm">
          Set <Code>NORINTH_API_KEY</Code> to an ingestion key from Identity & Integrations
          {value?.ingestion_key_hint ? <> (you have one: <Code>{value.ingestion_key_hint}…</Code>)</> : null}. Prompts and
          completions are hashed, never sent, unless you set <Code>NORINTH_CAPTURE_CONTENT=1</Code>.
        </Text>
        <Heading level={3} size="lg">Already on OpenTelemetry?</Heading>
        <CodeBlock label="OpenTelemetry collector config">{OTEL_SNIPPET}</CodeBlock>
      </Section>

      <Section
        title="What happens next"
        description="Once events arrive, the platform does the bookkeeping; people do the deciding."
      >
        <Stack as="ol" gap={3} style={{ margin: 0, paddingLeft: 20 }}>
          <Text as="li" size="md"><strong>Inventory fills itself.</strong> Every application, model, provider, workflow and agent seen in telemetry appears in Inventory. Anything unregistered is flagged as shadow AI.</Text>
          <Text as="li" size="md"><strong>Findings open automatically.</strong> Missing guardrails, failed evals, unregistered agents and off-policy tool use become risk findings with a severity, and a review task is routed to the right role.</Text>
          <Text as="li" size="md"><strong>Releases wait for evidence and a person.</strong> A deployment creates a gate. It is approved only by a reviewer who did not submit it, with a linked prompt version and a passing (signed) eval.</Text>
          <Text as="li" size="md"><strong>The audit packet writes itself.</strong> Inventory, AI-BOM, control evidence per framework, every decision with its rationale, and a verified audit trail, exported from Compliance.</Text>
        </Stack>
      </Section>
    </>
  );
}
