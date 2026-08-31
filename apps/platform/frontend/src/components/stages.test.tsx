// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { type ApprovalStage, StageWorkflow, policyPin, stageStatusLine } from "./stages";
import * as confirmModule from "./confirm";

function stage(overrides: Partial<ApprovalStage>): ApprovalStage {
  return {
    stage_id: "s0",
    stage_index: 0,
    required_role: "governance_reviewer",
    label: null,
    mode: "sequence",
    status: "open",
    policy_tenant: "acme",
    policy_version: 3,
    ...overrides,
  };
}

describe("stage text helpers", () => {
  it("says where a stage stands in plain words", () => {
    expect(stageStatusLine(stage({ status: "open" }))).toContain("Waiting on a governance reviewer");
    expect(stageStatusLine(stage({ status: "pending" }))).toContain("Opens when the previous stage is approved");
    expect(stageStatusLine(stage({ status: "approved", decided_by: "rev@acme.test", decided_at: "2026-08-30 10:00:00" }))).toContain(
      "Approved by rev@acme.test",
    );
  });

  it("pins the policy that materialized the stages", () => {
    expect(policyPin([stage({})])).toContain("acme v3");
    expect(policyPin([stage({ policy_tenant: "", policy_version: 1 })])).toContain("platform default v1");
  });
});

describe("StageWorkflow", () => {
  it("renders the ordered checklist and a decision panel only for open stages", () => {
    const stages = [
      stage({ stage_id: "s0", stage_index: 0, status: "approved", decided_by: "a@x", decided_at: "2026-08-30 10:00:00", label: "Security review" }),
      stage({ stage_id: "s1", stage_index: 1, status: "open", required_role: "risk_owner", label: "Risk acceptance" }),
      stage({ stage_id: "s2", stage_index: 2, status: "pending", required_role: "governance_admin" }),
    ];
    render(<StageWorkflow stages={stages} subjectLabel="Claims" onDecided={() => {}} />);
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent("Security review");
    expect(items[1]).toHaveTextContent("Risk acceptance");
    // one panel, for the open stage only
    expect(screen.getAllByTestId("stage-decision-panel")).toHaveLength(1);
    expect(screen.getByRole("heading", { name: /Your stage: Risk acceptance/ })).toBeInTheDocument();
  });

  it("requires a rationale, confirms, and posts the stage decision", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({} as any);
    vi.spyOn(confirmModule, "confirm").mockResolvedValue(true);
    const onDecided = vi.fn();
    render(<StageWorkflow stages={[stage({})]} subjectLabel="Claims" onDecided={onDecided} />);

    const approve = screen.getByRole("button", { name: "Approve stage" });
    expect(approve).toBeDisabled();
    await user.type(screen.getByLabelText("Stage decision rationale"), "Reviewed the security evidence in depth.");
    expect(approve).toBeEnabled();
    await user.click(approve);

    expect(post).toHaveBeenCalledWith("/api/approval-stages/s0/decide", {
      decision: "approve",
      rationale: "Reviewed the security evidence in depth.",
    });
    expect(onDecided).toHaveBeenCalled();
  });
});
