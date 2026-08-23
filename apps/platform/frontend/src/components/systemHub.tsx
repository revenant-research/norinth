import { Badge, Callout, Card, Chip, Eyebrow, Inline, Stack, Stat, StatGroup, Text } from "../design";

type Row = Record<string, any>;

const STAGE_COPY: Record<string, string> = {
  discovered: "Seen in production telemetry but never registered. Register it through Intake so it gets a risk tier and an accountable owner.",
  in_review: "Registered and waiting for the intake review decision.",
  approved: "Approved for use. Releases still need a gate decision.",
  recertified: "Recertified on schedule.",
  rejected: "The intake review rejected this use case.",
  retired: "Retired. Telemetry from it is a finding.",
};

// ai system hub header: what it is, what stage, who's accountable, what's
// blocking it. sits above the detail sections
export function SystemHubHeader({ detail }: { detail: Row }) {
  const app: Row = detail.application || {};
  const owners: Row[] = (detail.owners || []).filter((o: Row) => o.status === "assigned");
  const unowned: Row[] = (detail.owners || []).filter((o: Row) => o.status !== "assigned");
  const openRisks: Row[] = (detail.risks || []).filter((r: Row) => r.status === "open");
  const missingControls: Row[] = (detail.controls || []).filter((c: Row) => c.status === "missing");
  const pendingGates: Row[] = (detail.deployment_gates || []).filter((g: Row) => g.gate_status === "pending_review");
  const openReviews: Row[] = (detail.review_tasks || []).filter((t: Row) => t.status === "open");
  const openIncidents: Row[] = (detail.incidents || []).filter((i: Row) => i.status !== "closed");
  const stage = app.stage || "discovered";

  const blockers: string[] = [];
  if (stage === "discovered") blockers.push("not registered (no risk tier, no intake review)");
  if (unowned.length) blockers.push(`${unowned.length} owner role${unowned.length === 1 ? "" : "s"} unfilled`);
  if (openRisks.length) blockers.push(`${openRisks.length} open finding${openRisks.length === 1 ? "" : "s"}`);
  if (missingControls.length) blockers.push(`${missingControls.length} missing control${missingControls.length === 1 ? "" : "s"}`);
  if (openReviews.length) blockers.push(`${openReviews.length} review${openReviews.length === 1 ? "" : "s"} undecided`);
  if (openIncidents.length) blockers.push(`${openIncidents.length} open incident${openIncidents.length === 1 ? "" : "s"}`);

  return (
    <Stack gap={4}>
      <Card padding="md" tone="lead">
        <Inline justify="between" align="start" gap={4}>
          <Stack gap={2}>
            <Inline gap={2} align="center">
              <Eyebrow>AI system</Eyebrow>
              <Badge value={stage} />
              {app.risk_tier ? <Badge value={app.risk_tier}>{`tier: ${app.risk_tier}`}</Badge> : <Badge tone="neutral">no tier</Badge>}
              {app.environment ? <Chip>{app.environment}</Chip> : null}
            </Inline>
            <Text size="sm">{STAGE_COPY[stage] || ""}</Text>
            <Inline gap={2} aria-label="Accountable owners">
              {owners.length ? (
                owners.map((o: Row) => (
                  <Chip key={o.owner_assignment_id}>
                    {o.owner_role}: {o.owner_ref}
                  </Chip>
                ))
              ) : (
                <Text size="sm" tone="muted">No accountable owner named yet.</Text>
              )}
            </Inline>
          </Stack>
          <StatGroup columns={4}>
            <Stat label="Calls" value={app.model_calls ?? 0} />
            <Stat label="Errors" value={app.errors ?? 0} tone={app.errors ? "warning" : "ink"} />
            <Stat label="Open findings" value={openRisks.length} tone={openRisks.length ? "warning" : "ink"} />
            <Stat label="Gates pending" value={pendingGates.length} tone={pendingGates.length ? "warning" : "ink"} />
          </StatGroup>
        </Inline>
      </Card>
      {blockers.length ? (
        <Callout tone="warning" title="What is blocking this system">
          {blockers.join(" · ")}
        </Callout>
      ) : (
        <Callout tone="success" title="Nothing is blocking this system.">Registered, owned, no open findings, controls passing, no undecided reviews.</Callout>
      )}
    </Stack>
  );
}
