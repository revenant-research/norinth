import { useCallback, useState } from "react";

import { type PageMeta, getJson, postJson } from "../api";
import { Badge, Button, Callout, Card, Inline, SelectField, Stack, Text } from "../design";
import { toast } from "./toast";
import { RecordList, Section } from "./ui";
import { useResource } from "./useResource";

type Lead = {
  lead_id: string;
  name: string;
  email: string;
  organization: string;
  interest: string;
  message: string | null;
  status: string;
  created_at: string;
};

const STATUSES = ["new", "contacted", "qualified", "won", "lost"];
const INTEREST_LABEL: Record<string, string> = { pilot: "Start a pilot", demo: "Book a demo", pricing: "Enterprise pricing", security: "Security review" };

/** inbound pilot/demo requests from the landing page */
export function LeadsView() {
  const [filter, setFilter] = useState("");
  const query = useCallback(() => getJson<{ leads: Lead[]; page: PageMeta }>(`/api/admin/leads${filter ? `?status=${filter}` : ""}`), [filter]);
  const { value, error, reload } = useResource(query);
  const rows = value?.leads || [];

  async function setStatus(lead: Lead, status: string) {
    try {
      await postJson(`/api/admin/leads/${encodeURIComponent(lead.lead_id)}/status`, { status });
      toast.success(`${lead.organization}: ${status}`);
      reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not update.");
    }
  }

  return (
    <Section title="Pilot and demo requests" description="Submitted through the landing page. Reply within one business day; move each request through the funnel here.">
      {error ? <Callout tone="danger">{error}</Callout> : null}
      <Inline gap={3} align="end">
        <SelectField
          label="Show"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          options={[{ value: "", label: "All" }, ...STATUSES.map((s) => ({ value: s, label: s }))]}
        />
        <Text size="sm">{value ? `${value.page.total} request(s)` : ""}</Text>
      </Inline>
      <RecordList empty="No requests yet. They arrive from the landing page contact form." total={value?.page.total} label="requests">
        {rows.map((lead) => (
          <Card as="article" key={lead.lead_id} padding="sm" data-testid="lead-row">
            <Inline justify="between" align="start" gap={3}>
              <Stack gap={1}>
                <Inline gap={2} align="baseline">
                  <strong>{lead.organization}</strong>
                  <Badge value={lead.status} />
                  <Badge tone="signal">{INTEREST_LABEL[lead.interest] || lead.interest}</Badge>
                </Inline>
                <Text size="sm">
                  {lead.name} · <a href={`mailto:${lead.email}`}>{lead.email}</a> · {lead.created_at}
                </Text>
                {lead.message ? <Text size="sm" tone="muted">{lead.message}</Text> : null}
              </Stack>
              <Inline gap={2}>
                {STATUSES.filter((s) => s !== lead.status).map((s) => (
                  <Button key={s} variant="secondary" size="sm" onClick={() => setStatus(lead, s)}>
                    {s}
                  </Button>
                ))}
              </Inline>
            </Inline>
          </Card>
        ))}
      </RecordList>
    </Section>
  );
}
