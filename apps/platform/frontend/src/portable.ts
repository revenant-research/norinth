// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

// Hosts supply a session-authenticated transport. Machine credentials belong
// in the executor's secret store, never in a browser or these view components.
export type PortableRecord = {
  record_id: string;
  body_digest: string;
  tenant_id: string;
  kind: string;
  project: string;
  environment: string;
  integration_id: string;
  state: string;
  audited_at?: string;
  created_by: string;
  created_at: string;
  body: Record<string, any>;
};
export type Eligibility = {
  outcome: string;
  reasons: string[];
  checked_at: string;
  policy_id: string | null;
  evidence_ids: string[];
  enforcement: string;
};
export type SystemWorkspace = {
  system: PortableRecord;
  integration: PortableRecord;
  revisions: PortableRecord[];
  policies: PortableRecord[];
  authorizations: PortableRecord[];
  receipts: PortableRecord[];
  decisions: PortableRecord[];
  observations: PortableRecord[];
  verifications: PortableRecord[];
  packs: PortableRecord[];
  eligibility: Record<string, Eligibility>;
  [key: string]: any;
};
export type PortableTransport = <T>(
  path: string,
  method: "GET" | "POST",
  payload?: unknown,
) => Promise<T>;
export type PortableLinkResolver = (
  record: PortableRecord,
  relation: "source" | "evidence",
) => string | null;
export function safePortableLink(value: string | null): string | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
export function createPortableClient(transport: PortableTransport) {
  const segment = encodeURIComponent;
  return {
    systems: (scope: { project: string; environment: string }, offset = 0) =>
      transport<{ systems: PortableRecord[]; has_more: boolean }>(
        `/api/portable/systems?${new URLSearchParams({ ...Object.fromEntries(Object.entries(scope).filter(([, value]) => value)), offset: String(offset), limit: "50" })}`,
        "GET",
      ),
    workspace: (id: string, offset = 0) =>
      transport<SystemWorkspace>(
        `/api/portable/systems/${segment(id)}?offset=${offset}`,
        "GET",
      ),
    controls: (id: string, revision: string) =>
      transport<{ assessments: Record<string, any>[]; basis: string }>(
        `/api/portable/systems/${segment(id)}/controls?revision_id=${segment(revision)}`,
        "GET",
      ),
    decide: (
      id: string,
      decision: string,
      rationale: string,
      expected_body_digest: string,
    ) =>
      transport<{ record: PortableRecord }>(
        `/api/portable/records/${segment(id)}/${segment(decision)}`,
        "POST",
        { rationale, expected_body_digest },
      ),
    retryAudit: (id: string) =>
      transport<{ record: PortableRecord }>(
        `/api/portable/records/${segment(id)}/audit/retry`,
        "POST",
        {},
      ),
    integrations: (
      scope?: { project: string; environment: string },
      offset = 0,
    ) =>
      transport<{ integrations: PortableRecord[]; has_more: boolean }>(
        `/api/portable/integrations?${new URLSearchParams({ ...scope, offset: String(offset), limit: "100" })}`,
        "GET",
      ),
    register: (payload: unknown) =>
      transport<{ integration: PortableRecord; token: string }>(
        "/api/portable/integrations",
        "POST",
        payload,
      ),
    rotate: (id: string) =>
      transport<{ integration: PortableRecord; token: string }>(
        `/api/portable/integrations/${segment(id)}/rotate`,
        "POST",
        {},
      ),
    revoke: (id: string) =>
      transport<{ integration: PortableRecord }>(
        `/api/portable/integrations/${segment(id)}/revoke`,
        "POST",
        {},
      ),
    policy: (id: string, payload: unknown) =>
      transport<{ policy: PortableRecord }>(
        `/api/portable/systems/${segment(id)}/policies`,
        "POST",
        payload,
      ),
    pack: (scope: { project: string; environment: string }, payload: unknown) =>
      transport<{ pack: PortableRecord }>(
        `/api/portable/control-packs?${new URLSearchParams(scope)}`,
        "POST",
        payload,
      ),
  };
}
export type PortableClient = ReturnType<typeof createPortableClient>;

export function explainPortableReason(reason: string): string {
  const [code, detail] = reason.split(":", 2);
  const labels: Record<string, string> = {
    system_planned: "The system's stated purpose needs approval.",
    system_retired: "The system is retired and cannot be released or run.",
    executor_audit_pending:
      "The executor credential is waiting for its audit record and cannot grant permission yet.",
    executor_inactive: "The executor's integration is inactive.",
    governance_audit_pending:
      "A governance change is waiting for its audit record; it grants no permission yet.",
    no_active_runtime_policy:
      "No independently activated operating policy covers this system.",
    revision_requires_review:
      "An independent reviewer must approve this exact revision.",
    autonomy_exceeds_policy:
      "The revision requests more autonomy than the policy permits.",
    external_action_not_allowed:
      "The policy does not permit this revision's external effects.",
    human_checkpoint_required: "This revision must include a human checkpoint.",
    action_not_allowed:
      "The requested action is not allowed by this policy and executor registration.",
    resource_not_allowed:
      "The target resource is outside this revision's approved operating limits.",
    remediation_parameters_not_preapproved:
      "The correction's parameters do not match the values approved in policy.",
    invalid_action_parameters:
      "The action parameters do not match the executor's declared parameter types.",
    pending_legacy_evidence:
      "Previously received telemetry is still being processed, so permission cannot be established.",
  };
  const scoped: Record<string, string> = {
    missing_evidence: `No evidence has been received for ${detail} on this exact revision.`,
    stale_evidence: `The evidence for ${detail} has expired under the policy's freshness limit.`,
    unknown_evidence: `The evidence source could not establish whether ${detail} passed.`,
    nonpassing_evidence: `The latest evidence says ${detail} failed.`,
    pending_evidence_audit: `Evidence for ${detail} is waiting for its audit record.`,
    outside_policy: `The revision declares ${detail} that the operating policy does not allow.`,
    invalid_action_parameter: `The parameter ${detail} has an invalid type or value.`,
    legacy_blocker:
      "The explicitly linked existing system has an unresolved finding, missing control, or open change.",
  };
  return (
    labels[code] ||
    scoped[code] ||
    `Permission cannot be established: ${reason}.`
  );
}

export function portableStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    planned: "Purpose needs review",
    approved: "Approved",
    pending_review: "No human approval recorded",
    active: "Active",
    draft: "Draft",
    superseded: "Replaced",
    retired: "Retired",
    revoked: "Revoked",
    allow: "Allowed now",
    deny: "Blocked now",
    requires_review: "Needs review",
    indeterminate: "Cannot establish permission",
    audit_pending: "Audit recording pending",
    verification_pending: "Awaiting independent verification",
    verified: "Independently verified",
    reported_executed: "Executor reported execution",
    consumed: "Permission consumed",
    passing: "Passing",
    failed: "Failed",
    unknown: "Unknown",
    not_applicable: "Does not apply",
    recorded: "Recorded",
  };
  return labels[status] || status.replaceAll("_", " ");
}
