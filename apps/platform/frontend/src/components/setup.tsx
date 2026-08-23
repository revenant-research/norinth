import { useEffect, useState } from "react";

import { type User, changePassword, getJson, login, logout, postJson } from "../api";
import { Badge, Button, Callout, Card, Code, CodeBlock, Container, Eyebrow, FormGrid, Heading, Inline, Lede, Stack, Text, TextField } from "../design";
import { SecretReveal } from "./identity";
import styles from "./setup.module.css";

// first-run setup wizard, shown instead of the landing page until the first org
// exists. six steps, each backed by an api:
//   1 sign in as the platform admin (installer credentials)
//   2 set your own password (required if the bootstrap one is forced)
//   3 create your org and its first admin
//   4 create the first ingestion key
//   5 instrument one app and watch the first event arrive (live)
//   6 done

type Step = 1 | 2 | 3 | 4 | 5 | 6;

const STEP_TITLES: Record<Step, string> = {
  1: "Sign in as the platform administrator",
  2: "Choose your administrator password",
  3: "Create your organization",
  4: "Create an ingestion key",
  5: "Instrument one application",
  6: "You are set up",
};

function snippet(endpoint: string): string {
  return `pip install norinth-logger

import os
import norinth_logger as norinth

norinth.init(
    api_key=os.environ["NORINTH_API_KEY"],   # the key from the previous step
    endpoint="${endpoint}",
    project="my-project",
    environment="prod",
    service="my-service",
)
# OpenAI and Anthropic clients are auto-instrumented from here.`;
}

function otelSnippet(endpoint: string): string {
  return `exporters:
  otlphttp/norinth:
    endpoint: ${endpoint}/v1/otel
    headers:
      Authorization: "Bearer $NORINTH_API_KEY"`;
}

export function SetupWizard({ initialUser, onFinished }: { initialUser: User | null; onFinished: (user: User) => void }) {
  const [step, setStep] = useState<Step>(initialUser?.is_super_admin ? (initialUser.must_change_password ? 2 : 3) : 1);
  const [admin, setAdmin] = useState<User | null>(initialUser?.is_super_admin ? initialUser : null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [org, setOrg] = useState({ name: "", admin_email: "", admin_display_name: "", admin_password: "" });
  const [orgUser, setOrgUser] = useState<User | null>(null);
  const [key, setKey] = useState<string | null>(null);
  const [keyId, setKeyId] = useState<string | null>(null);
  const [firstSystem, setFirstSystem] = useState<string | null>(null);

  const endpoint = window.location.origin;

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  // step 5: poll until the org receives its first event
  useEffect(() => {
    if (step !== 5) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const state = await getJson<{ steps: Array<{ id: string; done: boolean }> }>("/api/onboarding");
        const sent = state.steps.find((s) => s.id === "send_events")?.done;
        if (sent && !cancelled) {
          const apps = await getJson<{ applications: Array<{ application_name?: string }> }>("/api/applications");
          setFirstSystem(apps.applications?.[0]?.application_name ?? "your first system");
          setStep(6);
        }
      } catch {
        /* keep polling */
      }
    };
    void tick();
    const id = window.setInterval(tick, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [step]);

  return (
    <div className={styles.page}>
      <Container>
        <div className={styles.frame}>
          <Stack gap={2}>
            <Eyebrow>Norinth · First-run setup</Eyebrow>
            <Heading level={1} size="2xl">{STEP_TITLES[step]}</Heading>
          </Stack>
          <ol className={styles.progress} aria-label="Setup progress">
            {([1, 2, 3, 4, 5, 6] as Step[]).map((n) => (
              <li key={n} className={n === step ? styles.current : n < step ? styles.done : undefined} aria-current={n === step ? "step" : undefined}>
                <span className={styles.dot} aria-hidden="true">{n < step ? "✓" : n}</span>
                <span className={styles.label}>{STEP_TITLES[n]}</span>
              </li>
            ))}
          </ol>

          <Card padding="lg" tone="lead">
            {error ? <Callout tone="danger">{error}</Callout> : null}

            {step === 1 ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    const user = await login(email, password);
                    if (!user.is_super_admin) throw new Error("Sign in with the platform administrator account printed by the installer.");
                    setAdmin(user);
                    setStep(user.must_change_password ? 2 : 3);
                  });
                }}
                aria-label="Administrator sign in"
              >
                <Stack gap={4}>
                  <Lede>The installer printed the administrator email and password (they are also in <Code>.env</Code> in the install directory).</Lede>
                  <FormGrid>
                    <TextField label="Administrator email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username" />
                    <TextField label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
                  </FormGrid>
                  <div><Button type="submit" size="lg" disabled={busy}>Continue</Button></div>
                </Stack>
              </form>
            ) : null}

            {step === 2 ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    if (newPassword.length < 12) throw new Error("Use at least 12 characters.");
                    await changePassword(password, newPassword);
                    setPassword(newPassword);
                    setAdmin(admin ? { ...admin, must_change_password: false } : admin);
                    setStep(3);
                  });
                }}
                aria-label="Set administrator password"
              >
                <Stack gap={4}>
                  <Lede>The platform administrator account manages organizations and the platform itself. It never touches an organization's governance data. Give it a password of your own.</Lede>
                  {!password ? <TextField label="Current password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" /> : null}
                  <TextField label="New password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={12} hint="At least 12 characters. Store it in your password manager." autoComplete="new-password" />
                  <div><Button type="submit" size="lg" disabled={busy}>Save and continue</Button></div>
                </Stack>
              </form>
            ) : null}

            {step === 3 ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    if (org.admin_password.length < 12) throw new Error("Use at least 12 characters for your organization password.");
                    await postJson("/api/setup/organization", org);
                    // hand off from the platform admin to the new org admin
                    await logout();
                    const user = await login(org.admin_email, org.admin_password);
                    setOrgUser(user);
                    setStep(4);
                  });
                }}
                aria-label="Create organization"
              >
                <Stack gap={4}>
                  <Lede>
                    An organization holds your AI systems, people, roles and evidence. You will be its first administrator. Administrators manage people and integrations; they cannot approve reviews or releases, so invite reviewers next.
                  </Lede>
                  <FormGrid>
                    <TextField label="Organization name" value={org.name} onChange={(e) => setOrg({ ...org, name: e.target.value })} required placeholder="e.g. Example Health" />
                    <TextField label="Your name" value={org.admin_display_name} onChange={(e) => setOrg({ ...org, admin_display_name: e.target.value })} required autoComplete="name" />
                    <TextField label="Your work email" type="email" value={org.admin_email} onChange={(e) => setOrg({ ...org, admin_email: e.target.value })} required autoComplete="email" hint="This becomes your organization administrator login." />
                    <TextField label="Your password" type="password" value={org.admin_password} onChange={(e) => setOrg({ ...org, admin_password: e.target.value })} required minLength={12} autoComplete="new-password" hint="At least 12 characters. Separate from the platform administrator password." />
                  </FormGrid>
                  <div><Button type="submit" size="lg" disabled={busy}>Create organization</Button></div>
                </Stack>
              </form>
            ) : null}

            {step === 4 ? (
              <Stack gap={4}>
                <Lede>
                  Applications send telemetry with an ingestion key. Each key is bound to <strong>{org.name}</strong>; telemetry can never be attributed to another organization. You can create more keys later under Identity & Integrations.
                </Lede>
                {key ? (
                  <>
                    <SecretReveal label="Ingestion key" value={key} onDismiss={() => setStep(5)} />
                    <Text size="sm">Key id <Code>{keyId}</Code>. Press "I've stored it" to continue.</Text>
                  </>
                ) : (
                  <div>
                    <Button
                      size="lg"
                      disabled={busy}
                      onClick={() =>
                        void run(async () => {
                          const result = await postJson<{ token: string; ingestion_key: { key_id: string } }>("/api/ingestion-keys", { name: "first application" });
                          setKey(result.token);
                          setKeyId(result.ingestion_key.key_id);
                        })
                      }
                    >
                      Create ingestion key
                    </Button>
                  </div>
                )}
              </Stack>
            ) : null}

            {step === 5 ? (
              <Stack gap={4}>
                <Lede>Add the SDK to one service, or point your OpenTelemetry collector at Norinth. This page updates itself the moment the first event arrives.</Lede>
                <Inline gap={2} align="center">
                  <span className={styles.pulse} aria-hidden="true" />
                  <Text tone="ink" size="md" role="status" aria-live="polite">Waiting for the first event from {org.name}…</Text>
                </Inline>
                <Heading level={3} size="lg">Python SDK</Heading>
                <CodeBlock label="SDK setup">{snippet(endpoint)}</CodeBlock>
                <Text size="sm">Set <Code>NORINTH_API_KEY</Code> to the key you just stored. Prompts and completions are hashed, never sent, unless you opt in.</Text>
                <Heading level={3} size="lg">Already on OpenTelemetry?</Heading>
                <CodeBlock label="OpenTelemetry collector">{otelSnippet(endpoint)}</CodeBlock>
                <Inline gap={3}>
                  <Button variant="secondary" onClick={() => setStep(6)}>Skip for now</Button>
                </Inline>
              </Stack>
            ) : null}

            {step === 6 ? (
              <Stack gap={4}>
                {firstSystem ? (
                  <Callout tone="success" title="First event received.">
                    <Inline gap={2} align="center"><Badge tone="success">discovered</Badge> <strong>{firstSystem}</strong> is in your inventory.</Inline>
                  </Callout>
                ) : (
                  <Callout tone="info">No events yet. The Getting started page keeps checking; instrument an application whenever you are ready.</Callout>
                )}
                <Lede>What happens next is governance, not plumbing: invite the people who decide, name an accountable owner per system, require signed evidence for releases, connect your identity provider, export your first audit packet. Getting started walks you through each one.</Lede>
                <Inline gap={3}>
                  <Button size="lg" onClick={() => orgUser && onFinished(orgUser)}>Open Getting started</Button>
                </Inline>
              </Stack>
            ) : null}
          </Card>
          <Text size="sm">Secrets shown here are never displayed again. Platform administrator credentials are in <Code>.env</Code> in the install directory; rotate them under Console → Accounts.</Text>
        </div>
      </Container>
    </div>
  );
}
