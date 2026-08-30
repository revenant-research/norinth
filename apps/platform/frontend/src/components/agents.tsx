// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useState } from "react";

import { type Scope, getJson, postJson } from "../api";
import { confirm } from "./confirm";
import { toast } from "./toast";
import { Badge, Chip, EmptyState, MetricCard, RecordList, Section } from "./ui";
import { useResource } from "./useResource";

// agent registry plus the runtime view that reconciles observed agents against
// it. issue badges map to the owasp top 10 for agentic apps so a reviewer sees
// why an agent is flagged

export type AgentIssue = "unregistered_agent" | "unauthorized_tool" | "agent_trifecta" | "autonomy_without_oversight";

export const ISSUE_LABELS: Record<AgentIssue, { label: string; owasp: string; tone: "danger" | "warn" }> = {
  unregistered_agent: { label: "Shadow agent (unregistered)", owasp: "ASI10 Rogue agents", tone: "danger" },
  unauthorized_tool: { label: "Tool outside allow-list", owasp: "ASI02/03 Tool misuse", tone: "danger" },
  agent_trifecta: { label: "Lethal trifecta, no human checkpoint", owasp: "ASI01/09", tone: "danger" },
  autonomy_without_oversight: { label: "High autonomy, no oversight", owasp: "ASI09 / EU AI Act Art 14", tone: "warn" },
};

type Posture = {
  agents: Array<Record<string, any>>;
  summary: { observed: number; registered: number; shadow: number; with_issues: number };
};

type Registry = { agents: Array<Record<string, any>>; autonomy_levels: Record<string, string> };

const EMPTY_FORM = {
  agent_name: "",
  owner_ref: "",
  application_name: "",
  description: "",
  autonomy_level: 1,
  allowed_tools: "",
  processes_untrusted_input: false,
  accesses_sensitive_data: false,
  can_act_externally: false,
  human_checkpoint: true,
};

/** true when the declared profile holds all three trifecta legs */
export function hasTrifecta(form: { processes_untrusted_input: boolean; accesses_sensitive_data: boolean; can_act_externally: boolean }): boolean {
  return form.processes_untrusted_input && form.accesses_sensitive_data && form.can_act_externally;
}

export function AgentsView({ scope, canRegister, canRetire }: { scope: Scope; canRegister: boolean; canRetire: boolean }) {
  const posture = useResource(() => getJson<Posture>("/api/agents/posture", scope));
  const registry = useResource(() => getJson<Registry>("/api/agent-registry", scope));
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [submitting, setSubmitting] = useState(false);

  function reloadAll() {
    posture.reload();
    registry.reload();
  }

  async function register(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await postJson("/api/agent-registry", {
        ...form,
        autonomy_level: Number(form.autonomy_level),
        allowed_tools: form.allowed_tools
          .split(",")
          .map((tool) => tool.trim())
          .filter(Boolean),
        application_name: form.application_name || null,
        description: form.description || null,
      });
      toast.success(`Agent "${form.agent_name}" registered.`);
      setForm({ ...EMPTY_FORM });
      reloadAll();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Registration failed.");
    } finally {
      setSubmitting(false);
    }
  }

  async function retire(agent: Record<string, any>) {
    const ok = await confirm({
      title: `Retire ${agent.agent_name}?`,
      body: "The agent will no longer be sanctioned. If it keeps running it will be flagged as a shadow agent.",
      confirmLabel: "Retire agent",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await postJson(`/api/agent-registry/${encodeURIComponent(agent.agent_id)}/retire`, {});
      toast.success("Agent retired.");
      reloadAll();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Retire failed.");
    }
  }

  const summary = posture.value?.summary;
  const agents = posture.value?.agents || [];
  const levels = registry.value?.autonomy_levels || {};
  const trifectaWarning = hasTrifecta(form) && !form.human_checkpoint;

  return (
    <>
      {posture.error ? <p className="feedback error" role="alert">{posture.error}</p> : null}
      <div className="metric-grid">
        <MetricCard label="Observed agents" value={summary?.observed ?? "–"} note="Seen at runtime" />
        <MetricCard label="Registered" value={summary?.registered ?? "–"} note="Sanctioned with an owner" />
        <MetricCard label="Shadow agents" value={summary?.shadow ?? "–"} note="Running but unregistered" />
        <MetricCard label="With issues" value={summary?.with_issues ?? "–"} note="OWASP Agentic findings" />
      </div>

      <Section title="Runtime posture" description="Every agent seen in telemetry, reconciled against the registry. Findings feed the risk register and the audit packet.">
        <RecordList empty="No agent activity has been observed yet. Agent runs arrive from the SDK (norinth.agent_run) or OpenTelemetry invoke_agent spans.">
          {agents.map((agent) => (
            <article className="record-card" key={agent.agent_name} data-testid="agent-card">
              <div className="record-main">
                <span className="record-title">{agent.agent_name}</span>
                <Badge value={agent.registered ? "registered" : "unregistered"} />
                {agent.autonomy_level !== undefined ? <Chip>autonomy L{agent.autonomy_level}</Chip> : null}
              </div>
              <p>
                {agent.application_name || "unknown application"} · {agent.run_count} run{agent.run_count === 1 ? "" : "s"}
                {agent.owner_ref ? ` · owner ${agent.owner_ref}` : ""}
                {agent.last_seen ? ` · last seen ${agent.last_seen}` : ""}
              </p>
              {agent.tools_used?.length ? <p>Tools used: {agent.tools_used.join(", ")}</p> : null}
              {agent.issues?.length ? (
                <ul className="issue-list" aria-label={`Issues for ${agent.agent_name}`}>
                  {(agent.issues as AgentIssue[]).map((issue) => (
                    <li key={issue} className={`issue ${ISSUE_LABELS[issue]?.tone ?? "warn"}`}>
                      <strong>{ISSUE_LABELS[issue]?.label ?? issue}</strong>
                      <span className="issue-ref">{ISSUE_LABELS[issue]?.owasp}</span>
                      {issue === "unauthorized_tool" && agent.unauthorized_tools?.length ? (
                        <span> — {agent.unauthorized_tools.join(", ")}</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="ok">No agentic-governance issues.</p>
              )}
            </article>
          ))}
        </RecordList>
      </Section>

      {canRegister ? (
        <Section title="Register an agent" description="Registration gives an agent an accountable owner, an autonomy bound, and a tool allow-list. Unregistered agents seen at runtime are flagged as shadow agents.">
          <form className="admin-form" onSubmit={register} aria-label="Register an agent">
            <label>
              Agent name
              <input value={form.agent_name} onChange={(e) => setForm({ ...form, agent_name: e.target.value })} required placeholder="claims-triage" />
            </label>
            <label>
              Accountable owner
              <input value={form.owner_ref} onChange={(e) => setForm({ ...form, owner_ref: e.target.value })} required placeholder="owner@company.com" />
            </label>
            <label>
              Application
              <input value={form.application_name} onChange={(e) => setForm({ ...form, application_name: e.target.value })} placeholder="Claims Review Assistant" />
            </label>
            <label>
              Autonomy level
              <select value={form.autonomy_level} onChange={(e) => setForm({ ...form, autonomy_level: Number(e.target.value) })}>
                {Object.entries(levels).length
                  ? Object.entries(levels).map(([level, label]) => (
                      <option key={level} value={level}>
                        L{level} — {label}
                      </option>
                    ))
                  : [0, 1, 2, 3, 4].map((level) => (
                      <option key={level} value={level}>
                        L{level}
                      </option>
                    ))}
              </select>
            </label>
            <label className="wide">
              Allowed tools (comma-separated)
              <input value={form.allowed_tools} onChange={(e) => setForm({ ...form, allowed_tools: e.target.value })} placeholder="lookup_claim, summarize" />
            </label>
            <label className="wide">
              Description
              <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </label>
            <fieldset className="wide check-group">
              <legend>Capability profile</legend>
              <label className="check-row">
                <input type="checkbox" checked={form.processes_untrusted_input} onChange={(e) => setForm({ ...form, processes_untrusted_input: e.target.checked })} />
                Processes untrusted input (web content, emails, user-provided documents)
              </label>
              <label className="check-row">
                <input type="checkbox" checked={form.accesses_sensitive_data} onChange={(e) => setForm({ ...form, accesses_sensitive_data: e.target.checked })} />
                Accesses sensitive or private data
              </label>
              <label className="check-row">
                <input type="checkbox" checked={form.can_act_externally} onChange={(e) => setForm({ ...form, can_act_externally: e.target.checked })} />
                Can change state or communicate externally (send, write, pay, call APIs)
              </label>
              <label className="check-row">
                <input type="checkbox" checked={form.human_checkpoint} onChange={(e) => setForm({ ...form, human_checkpoint: e.target.checked })} />
                A human checkpoint approves consequential actions
              </label>
            </fieldset>
            {trifectaWarning ? (
              <p className="feedback error wide" role="alert" data-testid="trifecta-warning">
                This profile combines untrusted input, sensitive data, and external action with no human checkpoint — the
                "lethal trifecta". It will be registered but flagged as a Critical finding (OWASP ASI01/ASI09).
              </p>
            ) : null}
            <button type="submit" disabled={submitting}>
              {submitting ? "Registering…" : "Register agent"}
            </button>
          </form>
        </Section>
      ) : null}

      <Section title="Agent registry" description="Sanctioned agents with their owners, autonomy bounds, and tool allow-lists.">
        {registry.error ? <p className="feedback error" role="alert">{registry.error}</p> : null}
        {(registry.value?.agents || []).length === 0 ? (
          <EmptyState>No agents registered yet.</EmptyState>
        ) : (
          <RecordList empty="">
            {(registry.value?.agents || []).map((agent) => (
              <article className="record-card" key={agent.agent_id} data-testid="registry-card">
                <div className="record-main">
                  <span className="record-title">{agent.agent_name}</span>
                  <Badge value={agent.status} />
                  <Chip>L{agent.autonomy_level}</Chip>
                </div>
                <p>
                  Owner {agent.owner_ref}
                  {agent.application_name ? ` · ${agent.application_name}` : ""} · tools: {agent.allowed_tools?.length ? agent.allowed_tools.join(", ") : "none allowed"}
                </p>
                <p>
                  {agent.processes_untrusted_input ? "untrusted input · " : ""}
                  {agent.accesses_sensitive_data ? "sensitive data · " : ""}
                  {agent.can_act_externally ? "external action · " : ""}
                  {agent.human_checkpoint ? "human checkpoint" : "no human checkpoint"}
                </p>
                {canRetire && agent.status === "active" ? (
                  <button type="button" className="secondary" onClick={() => retire(agent)}>
                    Retire
                  </button>
                ) : null}
              </article>
            ))}
          </RecordList>
        )}
      </Section>
    </>
  );
}
