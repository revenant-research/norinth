import { useState } from "react";

import { getJson, postJson, deleteJson } from "../api";
import { Badge, Button, Callout, Card, Checkbox, Code, FormGrid, Inline, SelectField, Stack, Text, TextField } from "../design";
import { confirm } from "./confirm";
import { SecretReveal } from "./identity";
import { toast } from "./toast";
import { RecordList, Section } from "./ui";
import { useResource } from "./useResource";

type Webhook = { webhook_id: string; name: string; url: string; events: string[]; format: string; status: string; created_at: string; last_delivery_at?: string | null; last_status?: string | null };
type Delivery = { id: number; channel: string; event_type: string; target: string; subject: string | null; status: string; attempts: number; last_error: string | null; created_at: string; sent_at: string | null };

const EVENT_LABELS: Record<string, string> = {
  "user.invited": "Person invited",
  "review.assigned": "Review assigned",
  "review.overdue": "Review overdue",
  "review.escalated": "Review escalated",
  "gate.approved": "Release gate approved",
  "gate.rejected": "Release gate rejected",
  "incident.opened": "Incident opened",
  "incident.closed": "Incident closed",
  test: "Test",
};

/**
 * Outbound notifications: signed webhooks (JSON for SIEM/ticketing, Slack
 * format for incoming webhooks) and the delivery log for both webhooks and
 * email, so an administrator can see what was sent, skipped or failed.
 */
export function WebhookSettings() {
  const hooks = useResource(() => getJson<{ webhooks: Webhook[]; events: string[]; smtp_configured: boolean }>("/api/org/webhooks"));
  const log = useResource(() => getJson<{ notifications: Delivery[]; smtp_configured: boolean }>("/api/org/notifications"));
  const [form, setForm] = useState({ name: "", url: "", format: "json" });
  const [selected, setSelected] = useState<string[]>(["gate.approved", "gate.rejected", "incident.opened", "review.escalated"]);
  const [secret, setSecret] = useState<string | null>(null);
  const events = hooks.value?.events || [];

  async function create(event: React.FormEvent) {
    event.preventDefault();
    try {
      const result = await postJson<{ secret: string }>("/api/org/webhooks", { ...form, events: selected });
      setSecret(result.secret);
      setForm({ name: "", url: "", format: "json" });
      hooks.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not create webhook.");
    }
  }

  async function test(hook: Webhook) {
    try {
      const result = await postJson<{ last_status: string | null }>(`/api/org/webhooks/${encodeURIComponent(hook.webhook_id)}/test`, {});
      toast[result.last_status === "ok" ? "success" : "error"](`Test delivery: ${result.last_status ?? "no response"}`);
      hooks.reload();
      log.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Test failed.");
    }
  }

  async function remove(hook: Webhook) {
    const ok = await confirm({ title: `Delete "${hook.name}"?`, body: "Deliveries to this URL stop immediately.", confirmLabel: "Delete", tone: "danger" });
    if (!ok) return;
    try {
      await deleteJson(`/api/org/webhooks/${encodeURIComponent(hook.webhook_id)}`);
      toast.success("Webhook deleted.");
      hooks.reload();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Delete failed.");
    }
  }

  return (
    <>
      <Section title="Notifications" description="Who gets told what. Email goes to the people a decision concerns; webhooks deliver the same events, signed, to Slack, your SIEM or a ticketing system.">
        {hooks.error ? <Callout tone="danger">{hooks.error}</Callout> : null}
        <Callout tone={hooks.value?.smtp_configured ? "success" : "warning"} title={hooks.value?.smtp_configured ? "Email is configured." : "Email is not configured."}>
          {hooks.value?.smtp_configured
            ? "Invites, review assignments, escalations, gate decisions and incidents are emailed to the people concerned."
            : "Set NORINTH_SMTP_HOST (and related variables) on the platform to email invites and notifications. Until then, invite links are shown to you to send yourself, and emails are recorded below as skipped."}
        </Callout>
        {secret ? <SecretReveal label="Webhook signing secret (verify X-Norinth-Signature: sha256=HMAC-SHA256(secret, body))" value={secret} onDismiss={() => setSecret(null)} /> : null}
        <form onSubmit={create} aria-label="Add webhook">
          <Stack gap={4}>
            <FormGrid>
              <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required placeholder="e.g. Splunk, #ai-governance" />
              <TextField label="URL" type="url" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required placeholder="https://hooks.slack.com/services/…" />
              <SelectField label="Format" value={form.format} onChange={(e) => setForm({ ...form, format: e.target.value })} options={[{ value: "json", label: "JSON (SIEM, ticketing, custom)" }, { value: "slack", label: "Slack incoming webhook" }]} />
            </FormGrid>
            <Inline gap={3} aria-label="Events">
              {events.filter((e) => e !== "test").map((e) => (
                <Checkbox key={e} label={EVENT_LABELS[e] || e} checked={selected.includes(e)} onChange={(ev) => setSelected(ev.target.checked ? [...selected, e] : selected.filter((x) => x !== e))} />
              ))}
            </Inline>
            <div><Button type="submit">Add webhook</Button></div>
          </Stack>
        </form>
        <RecordList empty="No webhooks yet." label="webhooks">
          {(hooks.value?.webhooks || []).map((hook) => (
            <Card as="article" key={hook.webhook_id} padding="sm" data-testid="webhook-row">
              <Inline justify="between" align="start" gap={3}>
                <Stack gap={1}>
                  <Inline gap={2} align="baseline">
                    <strong>{hook.name}</strong>
                    <Badge value={hook.status} />
                    <Badge tone="neutral">{hook.format}</Badge>
                    {hook.last_status ? <Badge tone={hook.last_status === "ok" ? "success" : "danger"}>{`last: ${hook.last_status}`}</Badge> : null}
                  </Inline>
                  <Text size="sm"><Code>{hook.url}</Code></Text>
                  <Text size="sm">{hook.events.map((e) => EVENT_LABELS[e] || e).join(", ")}</Text>
                </Stack>
                <Inline gap={2}>
                  <Button variant="secondary" size="sm" onClick={() => test(hook)}>Send test</Button>
                  <Button variant="danger" size="sm" onClick={() => remove(hook)}>Delete</Button>
                </Inline>
              </Inline>
            </Card>
          ))}
        </RecordList>
      </Section>
      <Section title="Recent deliveries" description="Every notification the platform tried to send, with its outcome. Failed deliveries retry with backoff for about an hour.">
        {log.error ? <Callout tone="danger">{log.error}</Callout> : null}
        <RecordList empty="Nothing sent yet." label="deliveries" pageSize={20}>
          {(log.value?.notifications || []).map((d) => (
            <Card as="article" key={d.id} padding="sm" data-testid="delivery-row">
              <Inline justify="between" gap={3} align="start">
                <Stack gap={1}>
                  <Inline gap={2} align="baseline">
                    <Badge tone="neutral">{d.channel}</Badge>
                    <strong>{EVENT_LABELS[d.event_type] || d.event_type}</strong>
                    <Text size="sm">→ {d.target}</Text>
                  </Inline>
                  <Text size="sm">{d.subject}</Text>
                  {d.last_error ? <Text size="sm" tone="muted">{d.last_error}</Text> : null}
                </Stack>
                <Stack gap={1} style={{ textAlign: "right" }}>
                  <Badge value={d.status === "sent" ? "success" : d.status === "failed" ? "failed" : d.status === "pending" ? "pending" : "skipped"}>{d.status}</Badge>
                  <Text size="xs">{d.sent_at || d.created_at}</Text>
                </Stack>
              </Inline>
            </Card>
          ))}
        </RecordList>
      </Section>
    </>
  );
}
