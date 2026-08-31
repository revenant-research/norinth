// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useState } from "react";

import { postJson } from "../api";
import { confirm } from "./confirm";
import { toast } from "./toast";
import { Badge, EmptyState } from "./ui";
import { formatTimestamp } from "./table";

// the approval-stage checklist a governance policy materializes for a review
// or a vendor. one implementation renders it everywhere stages appear, so the
// meaning of a stage reads the same on every surface

export type ApprovalStage = {
  stage_id: string;
  stage_index: number;
  required_role: string;
  label?: string | null;
  mode: string;
  status: "pending" | "open" | "approved" | "rejected";
  decided_by?: string | null;
  decided_at?: string | null;
  policy_tenant: string;
  policy_version: number;
};

export function stageTitle(stage: ApprovalStage): string {
  return stage.label || roleLabel(stage.required_role);
}

export function roleLabel(role: string): string {
  return role.replaceAll("_", " ");
}

/** one line saying where a stage stands, in plain words */
export function stageStatusLine(stage: ApprovalStage): string {
  if (stage.status === "approved") return `Approved by ${stage.decided_by} · ${formatTimestamp(stage.decided_at || "")}`;
  if (stage.status === "rejected") return `Rejected by ${stage.decided_by} · ${formatTimestamp(stage.decided_at || "")}`;
  if (stage.status === "open") return `Waiting on a ${roleLabel(stage.required_role)} · each stage needs a different person`;
  return stage.mode === "sequence" ? "Opens when the previous stage is approved" : "Pending";
}

export function policyPin(stages: ApprovalStage[]): string {
  if (!stages.length) return "";
  const first = stages[0];
  const source = first.policy_tenant === "" ? "platform default" : first.policy_tenant;
  return `Governed by policy ${source} v${first.policy_version}, in force when this review began`;
}

export function StageChecklist({ stages, dimmed = false }: { stages: ApprovalStage[]; dimmed?: boolean }) {
  if (!stages.length) return null;
  const ordered = [...stages].sort((a, b) => a.stage_index - b.stage_index);
  return (
    <div className="stage-list" data-testid="stage-checklist">
      <ol className="stage-steps" aria-label="Approval stages">
        {ordered.map((stage) => (
          <li key={stage.stage_id} className={`stage-step ${stage.status}${dimmed ? " dimmed" : ""}`}>
            <span className="stage-marker" aria-hidden="true">
              {stage.status === "approved" ? "✓" : stage.status === "rejected" ? "✕" : stage.stage_index + 1}
            </span>
            <div className="stage-body">
              <div className="stage-head">
                <strong>{stageTitle(stage)}</strong>
                <Badge value={stage.status} />
              </div>
              <p className="muted">{stageStatusLine(stage)}</p>
            </div>
          </li>
        ))}
      </ol>
      <p className="hint">{policyPin(ordered)}</p>
    </div>
  );
}

/** decide the open stage: rationale, then an explicit approve or reject */
export function StageDecisionPanel({
  stage,
  subjectLabel,
  onDecided,
}: {
  stage: ApprovalStage;
  subjectLabel: string;
  onDecided: () => void;
}) {
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const ready = rationale.trim().length >= 12;

  async function decide(decision: "approve" | "reject") {
    const ok = await confirm({
      title: decision === "approve" ? `Approve this stage?` : `Reject this review?`,
      body:
        decision === "approve"
          ? `You are deciding the "${stageTitle(stage)}" stage for ${subjectLabel}. Later stages still need their own reviewers; your decision is final and recorded in the audit trail.`
          : `Rejecting the "${stageTitle(stage)}" stage rejects ${subjectLabel} outright. The decision is final and recorded in the audit trail.`,
      confirmLabel: decision === "approve" ? "Approve stage" : "Reject",
      tone: decision === "approve" ? undefined : "danger",
    });
    if (!ok) return;
    setSubmitting(true);
    try {
      await postJson(`/api/approval-stages/${encodeURIComponent(stage.stage_id)}/decide`, { decision, rationale });
      toast.success(decision === "approve" ? "Stage approved." : "Review rejected.");
      onDecided();
    } catch (caught) {
      toast.error(caught instanceof Error ? caught.message : "Decision failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="workflow-panel" data-testid="stage-decision-panel">
      <div>
        <h3>Your stage: {stageTitle(stage)}</h3>
        <p className="muted">
          This stage requires the authority of the {roleLabel(stage.required_role)} role. You cannot decide it if you
          submitted the work or already decided another stage of it.
        </p>
      </div>
      <div className="inline-form workflow-action">
        <textarea
          placeholder="What you reviewed and why the decision holds"
          aria-label="Stage decision rationale"
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
        />
        <button
          disabled={!ready || submitting}
          title={ready ? undefined : "Enter a rationale before recording the decision"}
          onClick={() => decide("approve")}
        >
          Approve stage
        </button>
        <button
          className="secondary"
          disabled={!ready || submitting}
          title={ready ? undefined : "Enter a rationale before recording the decision"}
          onClick={() => decide("reject")}
        >
          Reject
        </button>
      </div>
    </div>
  );
}

/** the checklist plus a decision panel for every currently open stage */
export function StageWorkflow({
  stages,
  subjectLabel,
  onDecided,
}: {
  stages: ApprovalStage[];
  subjectLabel: string;
  onDecided: () => void;
}) {
  if (!stages.length) return <EmptyState>No approval stages exist for this record.</EmptyState>;
  const open = stages.filter((stage) => stage.status === "open");
  return (
    <>
      <StageChecklist stages={stages} />
      {open.map((stage) => (
        <StageDecisionPanel key={stage.stage_id} stage={stage} subjectLabel={subjectLabel} onDecided={onDecided} />
      ))}
    </>
  );
}
