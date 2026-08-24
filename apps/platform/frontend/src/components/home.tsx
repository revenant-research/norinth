import type { DashboardData, User } from "../api";
import { Badge, ButtonLink, Callout, Card, Eyebrow, Grid, Heading, Inline, Stack, Stat, StatGroup, Text, statusTone } from "../design";
import { Section } from "./ui";

// role-shaped home. everyone sees "needs you": items theirs to act on, from
// their permissions and assignments. admins also see org state and setup,
// owners see their systems, deciders see their queue

type Row = Record<string, any>;

function has(user: User, permission: string): boolean {
  return user.permissions.includes(permission);
}

function isOverdue(task: Row): boolean {
  return task.escalation_status === "overdue" || task.escalation_status === "escalated";
}

export function personaOf(user: User): "admin" | "decider" | "owner" | "viewer" {
  if (has(user, "user.manage")) return "admin";
  if (["review.decide", "gate.decide", "risk.accept", "incident.close", "control.attest"].some((p) => has(user, p))) return "decider";
  if (has(user, "owner.assign")) return "owner";
  return "viewer";
}

function ItemCard({ href, title, meta, status, tone }: { href: string; title: string; meta: string; status?: string; tone?: "warning" | "danger" }) {
  return (
    <Card as="a" padding="sm" interactive href={href}>
      <Inline justify="between" align="start" gap={3}>
        <Stack gap={1}>
          <strong>{title}</strong>
          <Text size="sm">{meta}</Text>
        </Stack>
        {status ? <Badge tone={tone ?? statusTone(status)}>{status}</Badge> : null}
      </Inline>
    </Card>
  );
}

function NeedsYou({ user, data }: { user: User; data: DashboardData }) {
  const mine = data.reviewTasks.filter((t) => t.status === "open" && t.assigned_to === user.user_ref);
  const roleQueue = data.reviewTasks.filter((t) => t.status === "open" && !t.assigned_to && has(user, "review.decide"));
  const gates = has(user, "gate.decide") ? data.deploymentGates.filter((g) => g.gate_status === "pending_review") : [];
  const incidents = has(user, "incident.close") ? data.incidents.filter((i) => i.status !== "closed") : [];
  const risks = has(user, "risk.accept") ? data.risks.filter((r) => r.status === "open" && ["high", "critical"].includes(String(r.severity).toLowerCase())) : [];
  const ownerFollowups = data.owners.filter((o) => o.status === "unassigned" && has(user, "owner.assign"));
  const total = mine.length + roleQueue.length + gates.length + incidents.length + risks.length + ownerFollowups.length;

  if (total === 0) {
    const why: Record<ReturnType<typeof personaOf>, string> = {
      admin: "Nothing is waiting on you. Reviews, gate decisions and incidents go to the people holding decision roles; owner follow-ups appear here when a system has nobody accountable.",
      decider: "Nothing is assigned to you right now. New reviews routed to your role, pending release gates and open incidents will appear here and you will be notified.",
      owner: "Nothing needs you right now. Systems waiting for an accountable owner will appear here.",
      viewer: "Nothing needs you. You have read access; ask an administrator for a decision or owner role if you should be acting on work.",
    };
    return <Callout tone="success" title="You are clear.">{why[personaOf(user)]}</Callout>;
  }

  return (
    <Grid min="320px" gap={4}>
      {mine.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">Assigned to you · {mine.length}</Eyebrow>
          {mine.slice(0, 5).map((t) => (
            <ItemCard key={t.task_id} href={`#review/${t.task_id}`} title={t.title} meta={`${t.application_name} · due ${t.due_at ? String(t.due_at).slice(0, 10) : "unscheduled"}`} status={isOverdue(t) ? t.escalation_status : t.priority} tone={isOverdue(t) ? "danger" : undefined} />
          ))}
          {mine.length > 5 ? <ButtonLink variant="link" size="sm" href="#myqueue">All {mine.length} in my queue</ButtonLink> : null}
        </Stack>
      ) : null}
      {roleQueue.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">Unassigned in your role · {roleQueue.length}</Eyebrow>
          {roleQueue.slice(0, 5).map((t) => (
            <ItemCard key={t.task_id} href={`#review/${t.task_id}`} title={t.title} meta={`${t.application_name} · ${t.assigned_role || "unrouted"}`} status={t.priority} />
          ))}
        </Stack>
      ) : null}
      {gates.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">Release gates to decide · {gates.length}</Eyebrow>
          {gates.slice(0, 5).map((g) => (
            <ItemCard key={g.gate_id} href={`#gate/${g.gate_id}`} title={`${g.application_name} / ${g.workflow_name}`} meta={g.required_reason || "ready for decision"} status={g.required_reason ? "blocked" : "ready"} tone={g.required_reason ? "warning" : undefined} />
          ))}
        </Stack>
      ) : null}
      {incidents.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">Open incidents · {incidents.length}</Eyebrow>
          {incidents.slice(0, 5).map((i) => (
            <ItemCard key={i.incident_id} href={`#incident/${i.incident_id}`} title={i.title} meta={`${i.application_name} · ${i.severity}`} status={i.severity} />
          ))}
        </Stack>
      ) : null}
      {risks.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">High-severity findings · {risks.length}</Eyebrow>
          {risks.slice(0, 5).map((r) => (
            <ItemCard key={r.finding_id || r.rule_id} href="#risk" title={r.risk || r.rule_id} meta={r.application_name} status={r.severity} />
          ))}
        </Stack>
      ) : null}
      {ownerFollowups.length ? (
        <Stack gap={2}>
          <Eyebrow tone="dim">Need an accountable owner · {ownerFollowups.length}</Eyebrow>
          {ownerFollowups.slice(0, 5).map((o) => (
            <ItemCard key={o.owner_assignment_id} href="#reviews" title={`${o.subject_type}: ${o.subject_name}`} meta={`${o.application_name} · ${o.owner_role}`} status="unassigned" />
          ))}
        </Stack>
      ) : null}
    </Grid>
  );
}

function Posture({ data }: { data: DashboardData }) {
  const systems = data.applications;
  const discovered = systems.filter((a) => a.stage === "discovered").length;
  const approved = systems.filter((a) => ["approved", "recertified"].includes(a.stage)).length;
  const unowned = data.owners.filter((o) => o.status === "unassigned").length;
  const pendingGates = data.deploymentGates.filter((g) => g.gate_status === "pending_review").length;
  const overdue = data.reviewTasks.filter((t) => t.status === "open" && isOverdue(t)).length;
  return (
    <StatGroup>
      <Stat label="AI systems" value={systems.length} note={`${approved} approved`} />
      <Stat label="Unregistered" value={discovered} note="seen in telemetry, never registered" tone={discovered ? "warning" : "ink"} />
      <Stat label="Without an owner" value={unowned} tone={unowned ? "warning" : "ink"} />
      <Stat label="Gates pending" value={pendingGates} />
      <Stat label="Reviews overdue" value={overdue} tone={overdue ? "danger" : "ink"} />
      <Stat label="Open incidents" value={data.summary.open_incidents ?? 0} note={`${data.summary.critical_incidents ?? 0} critical or high`} tone={data.summary.critical_incidents ? "danger" : "ink"} />
    </StatGroup>
  );
}

function MySystems({ user, data }: { user: User; data: DashboardData }) {
  const owned = new Set(data.owners.filter((o) => o.owner_ref === user.user_ref).map((o) => o.application_name));
  const systems = data.applications.filter((a) => owned.has(a.application_name));
  if (!systems.length) return null;
  return (
    <Section title="Systems you own" description="Where you are the accountable owner. Open one to see what is blocking its next release.">
      <Grid min="260px" gap={3}>
        {systems.map((a) => {
          const blockers = data.deploymentGates.filter((g) => g.application_name === a.application_name && g.gate_status === "pending_review").length;
          const open = data.risks.filter((r) => r.application_name === a.application_name && r.status === "open").length;
          return (
            <ItemCard key={a.entity_id} href={`#application/${a.entity_id}`} title={a.application_name} meta={`${open} open findings · ${blockers} gate${blockers === 1 ? "" : "s"} pending`} status={a.stage} />
          );
        })}
      </Grid>
    </Section>
  );
}

export function Home({ user, data, setupComplete }: { user: User; data: DashboardData; setupComplete: boolean | null }) {
  const persona = personaOf(user);
  const recent = data.decisions.slice(0, 5);
  return (
    <>
      <Section title="Needs you" description={persona === "viewer" ? "Work is routed by role; you currently have read access." : "Decisions and follow-ups that are yours. Everything here is also emailed to you when notifications are configured."}>
        <NeedsYou user={user} data={data} />
      </Section>
      {persona === "admin" ? (
        <Section title="Organization posture" description="How much of your AI estate is governed and where the gaps are.">
          {setupComplete === false ? (
            <Callout tone="info" title="Setup is not finished." action={<ButtonLink variant="secondary" size="sm" href="#guide">Open Getting started</ButtonLink>}>
              Reviewers, owners, signed evidence or your identity provider are still missing; the checklist shows which.
            </Callout>
          ) : null}
          <Posture data={data} />
        </Section>
      ) : null}
      <MySystems user={user} data={data} />
      {recent.length ? (
        <Section title="Recent decisions" description="The last decisions recorded in your organization, with who made them.">
          <Stack gap={2}>
            {recent.map((d) => (
              <Card key={`${d.target_id}-${d.created_at}`} padding="sm">
                <Inline justify="between" align="start" gap={3}>
                  <Stack gap={1}>
                    <Inline gap={2} align="baseline">
                      <Heading level={3} size="lg">{d.decision}</Heading>
                      <Badge value={d.target_type} />
                    </Inline>
                    <Text size="sm">{d.rationale}</Text>
                  </Stack>
                  <Text size="sm">{d.actor_ref}</Text>
                </Inline>
              </Card>
            ))}
          </Stack>
        </Section>
      ) : null}
    </>
  );
}
