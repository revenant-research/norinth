// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useEffect, useMemo, useState } from "react";

import { getJson, postJson } from "../api";
import { confirm } from "./confirm";
import { toast } from "./toast";
import { roleLabel } from "./stages";
import { Badge, Chip, EmptyState, Section, SkeletonCards } from "./ui";
import { formatTimestamp } from "./table";
import { useResource } from "./useResource";

// the governance policy page: who approves a new AI system, who approves a
// vendor, what a release must prove, and what the intake form asks. each
// approval path is edited directly as the pipeline of people it is — change a
// step's role in place, add or remove steps, reorder with the arrows. one
// primary action (review and put in force) shows the changes in plain
// sentences before anything takes effect, and every activation is
// hash-chained in the audit log. the stored document stays the truth; a raw
// copy sits behind a disclosure in History for auditors

export type StageDef = { role: string; label?: string };
export type TierRule = { stages: StageDef[]; mode?: string; recertify_days?: number | null };
export type FieldDef = {
  key: string;
  label?: string;
  type?: string;
  max_length?: number;
  required_tiers?: string[];
};
export type GateRule = { require_attested_evals?: boolean; max_open_material_changes?: number };
export type PolicyDoc = {
  schema: string;
  intake?: { tiers?: Record<string, TierRule>; fields?: FieldDef[] };
  gates?: { environments?: Record<string, GateRule> };
  vendors?: { stages?: StageDef[]; recertify_days?: number | null };
};

type PolicyMeta = {
  policy: { tenant_id: string; version: number; body: PolicyDoc; body_hash: string; activated_at?: string; source: string };
  decision_roles: string[];
  risk_tiers: string[];
  limits: { recertify_days_floor: number; max_stages: number; max_fields: number };
};

type PolicyVersion = {
  version: number;
  status: string;
  body: PolicyDoc;
  body_hash: string;
  created_by: string;
  created_at: string;
  activated_at?: string | null;
};

export const FIELD_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;
const FIELD_TYPES = ["string", "number", "boolean"];

export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function sameDoc(a: PolicyDoc, b: PolicyDoc): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** immutable document edits; every control routes through these */
export function updateTier(doc: PolicyDoc, tier: string, patch: Partial<TierRule>): PolicyDoc {
  const next = clone(doc);
  next.intake = next.intake || {};
  next.intake.tiers = next.intake.tiers || {};
  const current: TierRule = next.intake.tiers[tier] || { stages: [{ role: "governance_reviewer" }] };
  const merged: TierRule = { ...current, ...patch };
  if (merged.recertify_days === null || merged.recertify_days === undefined) delete merged.recertify_days;
  next.intake.tiers[tier] = merged;
  return next;
}

export function updateVendors(doc: PolicyDoc, patch: Partial<NonNullable<PolicyDoc["vendors"]>>): PolicyDoc {
  const next = clone(doc);
  const merged = { ...(next.vendors || { stages: [{ role: "governance_reviewer" }] }), ...patch };
  if (merged.recertify_days === null || merged.recertify_days === undefined) delete merged.recertify_days;
  next.vendors = merged;
  return next;
}

export function updateGateRule(doc: PolicyDoc, environment: string, patch: GateRule | null): PolicyDoc {
  const next = clone(doc);
  next.gates = next.gates || {};
  next.gates.environments = next.gates.environments || {};
  if (patch === null) {
    delete next.gates.environments[environment];
  } else {
    next.gates.environments[environment] = { ...(next.gates.environments[environment] || {}), ...patch };
  }
  return next;
}

export function setFields(doc: PolicyDoc, fields: FieldDef[]): PolicyDoc {
  const next = clone(doc);
  next.intake = next.intake || {};
  next.intake.fields = fields;
  return next;
}

/** stage-list edits shared by every pipeline */
export function stageListWith(
  stages: StageDef[],
  action: { add?: true; removeAt?: number; moveUp?: number; patchAt?: [number, Partial<StageDef>] },
  defaultRole: string,
): StageDef[] {
  const next = stages.map((stage) => ({ ...stage }));
  if (action.add) next.push({ role: defaultRole });
  if (action.removeAt !== undefined) next.splice(action.removeAt, 1);
  if (action.moveUp !== undefined && action.moveUp > 0) {
    const [moved] = next.splice(action.moveUp, 1);
    next.splice(action.moveUp - 1, 0, moved);
  }
  if (action.patchAt) {
    const [index, patch] = action.patchAt;
    next[index] = { ...next[index], ...patch };
    if (!next[index].label) delete next[index].label;
  }
  return next;
}

/** fast client-side problems, surfaced while typing; the server re-validates */
export function localIssues(doc: PolicyDoc, riskTiers: string[]): string[] {
  const issues: string[] = [];
  const tiers = doc.intake?.tiers || {};
  for (const tier of riskTiers) {
    const rule = tiers[tier];
    if (rule && (!rule.stages || rule.stages.length === 0)) issues.push(`${tier}: at least one approval step is required`);
  }
  if (doc.vendors && (!doc.vendors.stages || doc.vendors.stages.length === 0)) {
    issues.push("vendors: at least one approval step is required");
  }
  const seen = new Set<string>();
  for (const field of doc.intake?.fields || []) {
    if (!FIELD_KEY_RE.test(field.key || "")) issues.push(`field "${field.key || "(empty)"}": keys are lowercase identifiers like dpia_ref`);
    if (seen.has(field.key)) issues.push(`field "${field.key}": duplicate key`);
    seen.add(field.key);
  }
  return issues;
}

/** the plain-language reading of one tier's rule — what the policy means */
export function describeTier(tier: string, rule: TierRule): string {
  const count = rule.stages.length;
  const people =
    count === 1
      ? `one approval by a ${roleLabel(rule.stages[0].role)}`
      : `${count} approvals by different people, ${rule.mode === "parallel" ? "in any order" : "in order"}: ` +
        rule.stages.map((stage) => stage.label?.toLowerCase() || `a ${roleLabel(stage.role)}`).join(", then ");
  const recert = rule.recertify_days ? `, recertified every ${rule.recertify_days} days` : "";
  const article = /^[aeiou]/.test(tier) ? "An" : "A";
  return `${article} ${tier}-risk system needs ${people}${recert}.`;
}

export function describeVendors(rule: { stages?: StageDef[]; recertify_days?: number | null }): string {
  const stages = rule.stages || [];
  const count = stages.length;
  const people =
    count <= 1
      ? `one approval by a ${roleLabel(stages[0]?.role || "governance_reviewer")}`
      : `${count} approvals by different people, in order`;
  const recert = rule.recertify_days ? `, re-reviewed every ${rule.recertify_days} days` : "";
  return `A vendor needs ${people}${recert}.`;
}

/** which of a path's roles nobody holds — a path that cannot complete */
export function unstaffedRoles(stages: StageDef[], staffedRoles: Set<string> | null): string[] {
  if (staffedRoles === null) return [];
  return [...new Set(stages.map((stage) => stage.role))].filter((role) => !staffedRoles.has(role));
}

/**
 * one approval path, edited directly: each step is a card in the pipeline with
 * its role and label editable in place, arrows to reorder, x to remove, and a
 * ghost step at the end to add the next approver
 */
function PathPipeline({
  name,
  stages,
  mode,
  roles,
  maxStages,
  onChange,
  onMode,
}: {
  name: string;
  stages: StageDef[];
  mode?: string;
  roles: string[];
  maxStages: number;
  onChange: (stages: StageDef[]) => void;
  onMode?: (mode: string) => void;
}) {
  const parallel = mode === "parallel";
  return (
    <div className="pipeline" role="group" aria-label={`${name} approval path`}>
      {stages.map((stage, index) => (
        <span className="pipeline-item" key={index}>
          {index > 0 ? (
            <span className={`pipeline-connector${parallel ? " parallel" : ""}`} aria-hidden="true">
              {parallel ? "and" : "then"}
            </span>
          ) : null}
          <span className="pipeline-step">
            <span className="pipeline-step-head">
              <span className="stage-marker" aria-hidden="true">{index + 1}</span>
              <input
                className="pipeline-label"
                aria-label={`${name} step ${index + 1} label`}
                placeholder={roleLabel(stage.role)}
                value={stage.label || ""}
                maxLength={120}
                onChange={(event) => onChange(stageListWith(stages, { patchAt: [index, { label: event.target.value }] }, roles[0]))}
              />
              {index > 0 ? (
                <button
                  type="button"
                  className="pipeline-icon"
                  aria-label={`Move ${name} step ${index + 1} earlier`}
                  title="Move earlier"
                  onClick={() => onChange(stageListWith(stages, { moveUp: index }, roles[0]))}
                >
                  ←
                </button>
              ) : null}
              <button
                type="button"
                className="pipeline-icon"
                aria-label={`Remove ${name} step ${index + 1}`}
                disabled={stages.length === 1}
                title={stages.length === 1 ? "At least one approval is required" : "Remove this step"}
                onClick={() => onChange(stageListWith(stages, { removeAt: index }, roles[0]))}
              >
                ✕
              </button>
            </span>
            <select
              className="pipeline-role"
              aria-label={`${name} step ${index + 1} decided by`}
              value={stage.role}
              onChange={(event) => onChange(stageListWith(stages, { patchAt: [index, { role: event.target.value }] }, roles[0]))}
            >
              {roles.map((role) => (
                <option key={role} value={role}>
                  decided by {roleLabel(role)}
                </option>
              ))}
            </select>
          </span>
        </span>
      ))}
      {stages.length < maxStages ? (
        <span className="pipeline-item">
          <span className="pipeline-connector ghost" aria-hidden="true">{stages.length ? (parallel ? "and" : "then") : ""}</span>
          <button type="button" className="pipeline-add" onClick={() => onChange(stageListWith(stages, { add: true }, roles[0]))}>
            + Add approval
          </button>
        </span>
      ) : null}
      {stages.length > 1 && onMode ? (
        <span className="pipeline-order" role="radiogroup" aria-label={`${name} stage order`}>
          <button type="button" role="radio" aria-checked={!parallel} className={parallel ? "" : "on"} onClick={() => onMode("sequence")}>
            in order
          </button>
          <button type="button" role="radio" aria-checked={parallel} className={parallel ? "on" : ""} onClick={() => onMode("parallel")}>
            any order
          </button>
        </span>
      ) : null}
    </div>
  );
}

function RecertifyControl({
  name,
  days,
  floor,
  dueText,
  onChange,
}: {
  name: string;
  days?: number | null;
  floor: number;
  dueText: string;
  onChange: (days: number | null) => void;
}) {
  return (
    <label className="recertify-control">
      <span>↻ Recertify every</span>
      <input
        type="number"
        aria-label={`${name} recertification days`}
        min={floor}
        placeholder="never"
        value={days ?? ""}
        onChange={(event) => onChange(event.target.value === "" ? null : Number(event.target.value))}
      />
      <span>days</span>
      <span className="hint">{days ? dueText : "empty means approvals never expire"}</span>
    </label>
  );
}

function StaffingWarning({ stages, staffedRoles }: { stages: StageDef[]; staffedRoles: Set<string> | null }) {
  const missing = unstaffedRoles(stages, staffedRoles);
  if (!missing.length) return null;
  return (
    <p className="feedback error" role="alert">
      Nobody holds {missing.map(roleLabel).join(" or ")} in your organization yet, so this path cannot complete.{" "}
      <a href="#team">Assign the role in People &amp; access.</a>
    </p>
  );
}

function GateRulesEditor({ environments, onChange }: { environments: Record<string, GateRule>; onChange: (environment: string, patch: GateRule | null) => void }) {
  const [newEnvironment, setNewEnvironment] = useState("");
  const names = Object.keys(environments).sort((a, b) => (a === "*" ? 1 : b === "*" ? -1 : a.localeCompare(b)));
  return (
    <div className="stage-editor">
      {names.map((name) => (
        <div className="gate-rule-row" key={name} data-testid={`gate-rule-${name}`}>
          <strong className="gate-env">{name === "*" ? "All other environments" : name}</strong>
          <label className="check-row">
            <input
              type="checkbox"
              checked={Boolean(environments[name]?.require_attested_evals)}
              onChange={(event) => onChange(name, { require_attested_evals: event.target.checked })}
            />
            Only CI-signed (attested) eval evidence counts
          </label>
          {name === "*" ? (
            <span className="hint">always present</span>
          ) : (
            <button type="button" className="secondary" onClick={() => onChange(name, null)} aria-label={`Remove gate rule for ${name}`}>
              Remove
            </button>
          )}
        </div>
      ))}
      <div className="stage-editor-row">
        <input
          aria-label="Environment name"
          placeholder="environment, e.g. staging"
          value={newEnvironment}
          onChange={(event) => setNewEnvironment(event.target.value)}
        />
        <button
          type="button"
          className="secondary"
          disabled={!newEnvironment.trim() || Boolean(environments[newEnvironment.trim()])}
          onClick={() => {
            onChange(newEnvironment.trim(), { require_attested_evals: false, max_open_material_changes: 0 });
            setNewEnvironment("");
          }}
        >
          Add environment rule
        </button>
      </div>
      <p className="hint">
        These rules only add requirements. If your organization has registered a signing key, signed evidence stays
        required everywhere no matter what these boxes say.
      </p>
    </div>
  );
}

function FieldsEditor({
  fields,
  riskTiers,
  maxFields,
  onChange,
}: {
  fields: FieldDef[];
  riskTiers: string[];
  maxFields: number;
  onChange: (fields: FieldDef[]) => void;
}) {
  function patch(index: number, changes: Partial<FieldDef>) {
    const next = fields.map((field) => ({ ...field }));
    next[index] = { ...next[index], ...changes };
    onChange(next);
  }
  return (
    <div className="stage-editor">
      {fields.length === 0 ? (
        <p className="muted">
          No extra questions; the <a href="#intake">intake form</a> is unchanged. Add one to ask submitters
          for something your process needs, like a DPIA reference.
        </p>
      ) : null}
      {fields.map((field, index) => {
        const keyProblem = !FIELD_KEY_RE.test(field.key || "")
          ? "Keys are lowercase identifiers like dpia_ref"
          : fields.some((other, otherIndex) => other.key === field.key && otherIndex !== index)
            ? "Duplicate key"
            : "";
        return (
          <div className="field-editor-row" key={index} data-testid={`field-row-${index}`}>
            <div className="stage-editor-row">
              <input
                aria-label={`Field ${index + 1} key`}
                placeholder="key, e.g. dpia_ref"
                value={field.key}
                onChange={(event) => patch(index, { key: event.target.value })}
              />
              <input
                aria-label={`Field ${index + 1} label`}
                placeholder="Question shown on the intake form"
                maxLength={200}
                value={field.label || ""}
                onChange={(event) => patch(index, { label: event.target.value })}
              />
              <select aria-label={`Field ${index + 1} type`} value={field.type || "string"} onChange={(event) => patch(index, { type: event.target.value })}>
                {FIELD_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
              {(field.type || "string") === "string" ? (
                <span className="input-with-unit">
                  <input
                    type="number"
                    aria-label={`Field ${index + 1} maximum length`}
                    min={1}
                    max={4000}
                    value={field.max_length ?? 500}
                    onChange={(event) => patch(index, { max_length: Number(event.target.value) })}
                  />
                  <span>chars</span>
                </span>
              ) : null}
              <button type="button" className="secondary" aria-label={`Remove field ${index + 1}`} onClick={() => onChange(fields.filter((_, i) => i !== index))}>
                Remove
              </button>
            </div>
            {keyProblem ? (
              <p className="feedback error" role="alert">
                {keyProblem}
              </p>
            ) : null}
            <div className="check-group-inline">
              <span className="muted">Answer required for:</span>
              {riskTiers.map((tier) => (
                <label className="check-row" key={tier}>
                  <input
                    type="checkbox"
                    checked={(field.required_tiers || []).includes(tier)}
                    onChange={(event) => {
                      const current = new Set(field.required_tiers || []);
                      if (event.target.checked) current.add(tier);
                      else current.delete(tier);
                      patch(index, { required_tiers: riskTiers.filter((t) => current.has(t)) });
                    }}
                  />
                  {tier}
                </label>
              ))}
            </div>
          </div>
        );
      })}
      <div className="flag-action">
        <button
          type="button"
          className="secondary"
          disabled={fields.length >= maxFields}
          onClick={() => onChange([...fields, { key: "", label: "", type: "string", max_length: 500, required_tiers: [] }])}
        >
          Add question
        </button>
        <span className="hint">Typed and length-capped; never for PHI or other regulated content.</span>
      </div>
    </div>
  );
}

function VersionHistory({
  versions,
  activeVersion,
  activeBody,
  onActivate,
  onShowDiff,
}: {
  versions: PolicyVersion[];
  activeVersion: number | null;
  activeBody: PolicyDoc;
  onActivate: (version: PolicyVersion) => void;
  onShowDiff: (version: PolicyVersion) => void;
}) {
  return (
    <>
      {versions.length === 0 ? (
        <EmptyState>
          Nothing here yet. Your organization runs on the platform default: one reviewer approval per risk level, and
          approvals never expire. Change a path and put it in force to start your history.
        </EmptyState>
      ) : (
        <div className="record-list">
          {versions.map((row) => (
            <article className="record-card" key={row.version} data-testid={`policy-version-${row.version}`}>
              <div className="record-main">
                <span className="record-title">Version {row.version}</span>
                <Badge value={row.status} />
                <Chip>sha256 {row.body_hash.slice(0, 12)}…</Chip>
              </div>
              <p className="muted">
                Drafted by {row.created_by} · {formatTimestamp(row.created_at)}
                {row.activated_at ? ` · activated ${formatTimestamp(row.activated_at)}` : ""}
              </p>
              <div className="inline-form">
                <button type="button" className="secondary" onClick={() => onShowDiff(row)}>
                  What changed
                </button>
                {row.status === "draft" ? (
                  <button type="button" onClick={() => onActivate(row)}>
                    Put in force…
                  </button>
                ) : null}
                {row.version === activeVersion ? <span className="ok">In force</span> : null}
              </div>
            </article>
          ))}
        </div>
      )}
      <details className="raw-doc">
        <summary>Raw policy document (for auditors and the API)</summary>
        <pre className="json-editor" aria-label="Raw policy document">{JSON.stringify(activeBody, null, 2)}</pre>
      </details>
    </>
  );
}

export const POLICY_TABS = [
  { id: "paths", label: "Approval paths" },
  { id: "vendors", label: "Vendor reviews" },
  { id: "gates", label: "Release gates" },
  { id: "intake", label: "Intake form" },
  { id: "history", label: "History" },
] as const;

export function policyTabFromHash(): string {
  const parts = (window.location.hash || "").slice(1).split("/");
  const requested = parts[0] === "policy" ? parts[1] : "";
  return POLICY_TABS.some((tab) => tab.id === requested) ? requested : "paths";
}

/** plain-language guidance shown at the top of each view: what it is, how it
 * connects to the rest of Norinth, and what to do */
function TabGuide({ what, wiring, steps }: { what: React.ReactNode; wiring: React.ReactNode; steps: React.ReactNode[] }) {
  return (
    <div className="tab-guide" data-testid="tab-guide">
      <div className="tab-guide-text">
        <p>{what}</p>
        <p className="muted">{wiring}</p>
      </div>
      <div className="tab-guide-steps">
        <strong>What to do</strong>
        <ol>
          {steps.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      </div>
    </div>
  );
}

const POLICY_GUIDES: Record<string, { what: React.ReactNode; wiring: React.ReactNode; steps: React.ReactNode[] }> = {
  paths: {
    what: "An approval path is the list of people who must sign off before an AI system is approved. Each risk level has its own path, so riskier systems can require more sign-offs.",
    wiring: (
      <>
        Norinth spots AI systems from the usage they report. When someone submits one on the{" "}
        <a href="#intake">Register a system</a> page, it gets a risk level, and that level's path becomes the review
        steps in <a href="#reviews">Reviews &amp; owners</a>. A different person must decide each step, and the person
        who submitted can never decide. People are kept in the loop by email and your connected webhooks: reviewers
        hear when their step opens, get reminders when a review is overdue, an administrator is alerted if it sits too
        long, and the submitter hears the final decision.
      </>
    ),
    steps: [
      <>
        Pick who decides each step. The list only offers roles allowed to decide reviews, and{" "}
        <a href="#team">People &amp; access</a> controls who holds each role.
      </>,
      "Use the label to say what a step means, like Security review. Press Add approval for another sign-off, and the arrows to change the order.",
      "With more than one step, choose whether they open one at a time (in order) or all at once (any order).",
      "Type a number of days to make approvals expire. Leave it empty and approvals last forever.",
    ],
  },
  vendors: {
    what: "Vendors are the companies behind the AI models your systems use, like OpenAI or Anthropic. This path decides who signs off before a vendor counts as approved.",
    wiring: (
      <>
        Norinth lists every model provider your systems actually call on the <a href="#vendors">AI vendors</a> page. A
        provider without an approved vendor becomes a risk finding on every system that uses it, and open findings stop
        releases.
      </>
    ),
    steps: [
      "Pick who signs off on vendors.",
      "Type a number of days to make vendor approvals expire. An expired approval stops counting until the vendor is reviewed again.",
      <>
        Put your changes in force, then review vendors on the <a href="#vendors">AI vendors</a> page.
      </>,
    ],
  },
  gates: {
    what: "A release gate stops a deployment from shipping until the proof is there. Every gate already requires a recorded prompt version, a passing eval (a quality check your systems report) for that exact build, and no open findings, missing controls, or unreviewed changes.",
    wiring: (
      <>
        The rules here add to that, per environment. They can only make gates stricter, never looser. Gates live on the{" "}
        <a href="#deployments">Release gates</a> page, and your build pipeline can check a gate before it ships.
      </>
    ),
    steps: [
      <>
        Tick the box for environments where an eval only counts if your build system signed it. Register the signing key
        under <a href="#identity">Identity &amp; integrations</a>.
      </>,
      "Add a row for an environment that needs its own rule. Everything else follows the All other environments row.",
    ],
  },
  intake: {
    what: "These are extra questions people answer when they submit a system for review. They appear under the built-in questions on the Register a system page.",
    wiring: (
      <>
        Answers are saved with the system and shown to reviewers. A required question blocks submission until it is
        answered. Try the form on the <a href="#intake">Register a system</a> page after you put changes in force.
      </>
    ),
    steps: [
      "Press Add question. The key is a short id for the API. The label is the question people see.",
      "Pick the answer type. For text answers, set a length limit.",
      "Tick the risk levels where an answer is required.",
      "Never ask for patient data or anything else sensitive. Answers are labels, not records.",
    ],
  },
  history: {
    what: "Every version of your rules, kept forever. The version marked In force governs new work. Older versions stay here as the record.",
    wiring: (
      <>
        A review keeps the version it started under, so you can always tell which rules applied to any decision. Every
        activation is written to the <a href="#audit">Audit log</a> in a way that cannot be quietly edited, and auditor
        exports include this history.
      </>
    ),
    steps: [
      "Press What changed on a version to see the exact differences, line by line.",
      "A draft is saved but not in force yet. Press Put in force to make it the active version.",
      "The raw document at the bottom is for auditors and scripts, not for day-to-day editing.",
    ],
  },
};

export function PolicyView() {
  const meta = useResource(() => getJson<PolicyMeta>("/api/governance-policy"));
  const history = useResource(() => getJson<{ versions: PolicyVersion[] }>("/api/governance-policy/versions"));
  // live wiring: systems per tier, reviews in flight under the policy, and
  // whether anyone actually holds the roles the paths name
  const intake = useResource(() => getJson<{ intake: Array<Record<string, any>> }>("/api/intake"));
  // discovery is the source of truth: systems Norinth has seen in telemetry
  // that nobody has submitted yet are the estate this policy does not govern
  const applications = useResource(() => getJson<{ applications: Array<Record<string, any>> }>("/api/applications"));
  const liveStages = useResource(() =>
    getJson<{ approval_stages: Array<Record<string, any>> }>("/api/approval-stages?subject_type=review_task"),
  );
  const staffing = useResource(() =>
    getJson<{ role_assignments: Array<Record<string, any>> }>("/api/org/role-assignments").catch(() => null),
  );

  const [doc, setDoc] = useState<PolicyDoc | null>(null);
  const [serverErrors, setServerErrors] = useState<string[]>([]);
  const [diffView, setDiffView] = useState<{ label: string; lines: string[] } | null>(null);
  const [saving, setSaving] = useState(false);
  // one concern per view; edits accumulate across views into the one working
  // document and go in force together. deep-linkable as #policy/<view>
  const [tab, setTab] = useState<string>(() => policyTabFromHash());
  useEffect(() => {
    const onHashChange = () => setTab(policyTabFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const inForce = meta.value?.policy || null;
  const baseline = inForce?.body || null;
  const working = doc ?? baseline;
  const dirty = Boolean(working && baseline && !sameDoc(working, baseline));
  const issues = useMemo(
    () => (working && meta.value ? localIssues(working, meta.value.risk_tiers) : []),
    [working, meta.value],
  );

  const tierCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const record of intake.value?.intake || []) {
      if (record.status === "retired") continue;
      counts[record.risk_tier] = (counts[record.risk_tier] || 0) + 1;
    }
    return counts;
  }, [intake.value]);

  const inFlightReviews = useMemo(() => {
    const rows = liveStages.value?.approval_stages || [];
    return new Set(rows.filter((stage) => stage.status === "open" || stage.status === "pending").map((stage) => stage.subject_id)).size;
  }, [liveStages.value]);

  const discoveredUngoverned = useMemo(
    () => (applications.value?.applications || []).filter((application) => application.stage === "discovered").length,
    [applications.value],
  );

  const staffedRoles = useMemo(() => {
    if (!staffing.value) return null; // not readable for this account; skip the check
    const active = new Set<string>();
    for (const assignment of staffing.value.role_assignments || []) {
      if (assignment.status === "active") active.add(assignment.role);
    }
    return active;
  }, [staffing.value]);

  function edit(next: PolicyDoc) {
    setDoc(next);
    setServerErrors([]);
  }

  function reloadAll() {
    meta.reload();
    history.reload();
    liveStages.reload();
  }

  /** the one primary action: save the working copy as the next version, show
   * exactly what changes in plain terms, and activate on confirmation. if the
   * confirmation is declined the draft stays in History for later */
  async function reviewAndPutInForce() {
    if (!working) return;
    setSaving(true);
    try {
      const draft = await postJson<{ policy: PolicyVersion }>("/api/governance-policy/draft", { body: working });
      let lines: string[] = [];
      try {
        const diff = await getJson<{ diff: string[] }>(`/api/governance-policy/diff?to_version=${draft.policy.version}`);
        lines = diff.diff;
      } catch {
        lines = ["(change summary unavailable)"];
      }
      const ok = await confirm({
        title: "Put these rules in force?",
        body:
          "New reviews, release gates and vendor reviews follow the new rules immediately; reviews already in flight keep the rules they started under. The activation is recorded in the audit log.\n\nChanges:\n" +
          lines.slice(0, 12).join("\n") +
          (lines.length > 12 ? `\n…and ${lines.length - 12} more` : ""),
        confirmLabel: "Put in force",
      });
      if (!ok) {
        toast.success(`Saved as draft v${draft.policy.version} without activating.`);
        setDoc(null);
        reloadAll();
        window.location.hash = "#policy/history";
        setTab("history");
        return;
      }
      await postJson(`/api/governance-policy/versions/${draft.policy.version}/activate`, {});
      toast.success(`Your policy v${draft.policy.version} is now in force.`);
      setDoc(null);
      setServerErrors([]);
      reloadAll();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Could not save the policy.";
      setServerErrors(message.split("; "));
      toast.error("The policy has problems; see the list above the paths.");
    } finally {
      setSaving(false);
    }
  }

  async function activate(version: PolicyVersion) {
    let lines: string[] = [];
    try {
      const diff = await getJson<{ diff: string[] }>(`/api/governance-policy/diff?to_version=${version.version}`);
      lines = diff.diff;
    } catch {
      lines = ["(change summary unavailable)"];
    }
    const ok = await confirm({
      title: `Put version ${version.version} in force?`,
      body:
        "New reviews, release gates and vendor reviews follow it immediately; reviews already in flight keep the rules they started under.\n\nChanges:\n" +
        lines.slice(0, 12).join("\n") +
        (lines.length > 12 ? `\n…and ${lines.length - 12} more` : ""),
      confirmLabel: "Put in force",
    });
    if (!ok) return;
    try {
      await postJson(`/api/governance-policy/versions/${version.version}/activate`, {});
      toast.success(`Policy v${version.version} is now in force.`);
      setDoc(null);
      setDiffView(null);
      reloadAll();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Activation failed.");
    }
  }

  async function showDiff(version: PolicyVersion) {
    try {
      const diff = await getJson<{ diff: string[] }>(`/api/governance-policy/diff?to_version=${version.version}`);
      setDiffView({ label: `v${version.version} vs in force`, lines: diff.diff });
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Could not load the change summary.");
    }
  }

  if (meta.error) return <p className="feedback error" role="alert">{meta.error}</p>;
  if (!meta.value || !working || !inForce) {
    return (
      <Section title="Governance policy" description="Loading the policy in force for your organization.">
        <SkeletonCards count={3} />
      </Section>
    );
  }
  const { decision_roles: roles, risk_tiers: riskTiers, limits } = meta.value;
  const tiers = working.intake?.tiers || {};
  const environments = working.gates?.environments || { "*": {} };
  const vendors = working.vendors || { stages: [{ role: "governance_reviewer" }] };
  const fields = working.intake?.fields || [];
  const activeVersion = inForce.source === "tenant" ? inForce.version : null;
  const governedCount = Object.values(tierCounts).reduce((a, b) => a + b, 0);
  const draftCount = (history.value?.versions || []).filter((row) => row.status === "draft").length;

  return (
    <>
      <div className="policy-toolbar" data-testid="policy-toolbar">
        <div className="policy-status">
          <strong>
            {inForce.source === "tenant" ? `Your policy v${inForce.version} is in force` : "The platform default is in force"}
          </strong>
          <span className="muted">
            {intake.value ? `Governing ${governedCount} system${governedCount === 1 ? "" : "s"}` : ""}
            {liveStages.value ? ` · ${inFlightReviews} review${inFlightReviews === 1 ? "" : "s"} in flight` : ""}
            {" · every rule change is recorded in the "}
            <a href="#audit">audit log</a>
          </span>
          {discoveredUngoverned > 0 ? (
            <span className="feedback error" role="alert">
              {discoveredUngoverned} system{discoveredUngoverned === 1 ? "" : "s"} seen running in production{" "}
              {discoveredUngoverned === 1 ? "is" : "are"} not under this policy yet, because nobody has submitted{" "}
              {discoveredUngoverned === 1 ? "it" : "them"} for review. <a href="#inventory">See the inventory.</a>
            </span>
          ) : null}
        </div>
        <div className="inline-form">
          {dirty ? (
            <>
              <Badge value="unsaved changes" />
              <button type="button" className="secondary" onClick={() => { setDoc(null); setServerErrors([]); }}>
                Discard
              </button>
              <button
                type="button"
                disabled={issues.length > 0 || saving}
                title={issues.length ? "Fix the problems listed first" : undefined}
                onClick={reviewAndPutInForce}
              >
                {saving ? "Saving…" : "Review & put in force"}
              </button>
            </>
          ) : (
            <span className="muted">Change anything below, then review and put it in force.</span>
          )}
        </div>
      </div>
      {issues.length || serverErrors.length ? (
        <div className="partial-load" role="alert" data-testid="policy-problems">
          <strong>Problems to fix before these rules can take force.</strong>
          <ul>
            {[...issues, ...serverErrors].map((issue) => (
              <li key={issue}>{issue}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <nav className="subnav" aria-label="Policy sections">
        {POLICY_TABS.map((entry) => (
          <a
            key={entry.id}
            href={`#policy/${entry.id}`}
            aria-current={tab === entry.id ? "page" : undefined}
            className={tab === entry.id ? "on" : ""}
            onClick={() => setTab(entry.id)}
          >
            {entry.label}
            {entry.id === "history" && draftCount > 0 ? <Chip>{draftCount} draft{draftCount === 1 ? "" : "s"}</Chip> : null}
          </a>
        ))}
      </nav>
      {POLICY_GUIDES[tab] ? <TabGuide {...POLICY_GUIDES[tab]} /> : null}

      {tab === "paths" ? (
        <div className="path-rows" data-testid="policy-paths">
          {riskTiers.map((tier) => {
            const rule = tiers[tier] || { stages: [{ role: "governance_reviewer" }] };
            const count = tierCounts[tier] || 0;
            return (
              <div className="path-row" key={tier} data-testid={`tier-card-${tier}`}>
                <div className="path-meta">
                  <h3>{tier} risk</h3>
                  <Chip>{intake.value ? `${count} system${count === 1 ? "" : "s"} today` : "…"}</Chip>
                  <p className="muted path-sentence">{describeTier(tier, rule)}</p>
                </div>
                <div className="path-build">
                  <PathPipeline
                    name={`${tier} tier`}
                    stages={rule.stages}
                    mode={rule.mode}
                    roles={roles}
                    maxStages={limits.max_stages}
                    onChange={(stages) => edit(updateTier(working, tier, { stages }))}
                    onMode={(mode) => edit(updateTier(working, tier, { mode }))}
                  />
                  <RecertifyControl
                    name={`${tier} tier`}
                    days={rule.recertify_days}
                    floor={limits.recertify_days_floor}
                    dueText="a new review opens by itself when time runs out"
                    onChange={(days) => edit(updateTier(working, tier, { recertify_days: days }))}
                  />
                  <StaffingWarning stages={rule.stages} staffedRoles={staffedRoles} />
                </div>
              </div>
            );
          })}
        </div>
      ) : null}

      {tab === "vendors" ? (
        <div className="path-rows">
          <div className="path-row">
            <div className="path-meta">
              <h3>vendor review</h3>
              <a className="linklike" href="#vendors">Open AI vendors</a>
              <p className="muted path-sentence">{describeVendors(vendors)}</p>
            </div>
            <div className="path-build">
              <PathPipeline
                name="vendor"
                stages={vendors.stages || []}
                roles={roles}
                maxStages={limits.max_stages}
                onChange={(stages) => edit(updateVendors(working, { stages }))}
              />
              <RecertifyControl
                name="vendor"
                days={vendors.recertify_days}
                floor={limits.recertify_days_floor}
                dueText="an expired approval stops counting until the vendor is reviewed again"
                onChange={(days) => edit(updateVendors(working, { recertify_days: days }))}
              />
              <StaffingWarning stages={vendors.stages || []} staffedRoles={staffedRoles} />
            </div>
          </div>
        </div>
      ) : null}

      {tab === "gates" ? (
        <GateRulesEditor environments={environments} onChange={(environment, patch) => edit(updateGateRule(working, environment, patch))} />
      ) : null}

      {tab === "intake" ? (
        <FieldsEditor fields={fields} riskTiers={riskTiers} maxFields={limits.max_fields} onChange={(next) => edit(setFields(working, next))} />
      ) : null}

      {tab === "history" ? (
        <>
          {diffView ? (
            <div className="diff-panel" data-testid="policy-diff-panel">
              <strong>Changes: {diffView.label}</strong>
              <ul className="gap-list" data-testid="policy-diff">
                {diffView.lines.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <button type="button" className="secondary" onClick={() => setDiffView(null)}>
                Close
              </button>
            </div>
          ) : null}
          {history.error ? <p className="feedback error" role="alert">{history.error}</p> : null}
          <VersionHistory
            versions={history.value?.versions || []}
            activeVersion={activeVersion}
            activeBody={inForce.body}
            onActivate={activate}
            onShowDiff={showDiff}
          />
        </>
      ) : null}
    </>
  );
}
