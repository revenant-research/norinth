// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Home, personaOf } from "./home";

const base = { user_ref: "u", display_name: "U", email: "u@x", tenant_id: "acme", platform_role: null, must_change_password: false, is_super_admin: false };
const data: any = {
  summary: { open_incidents: 1, critical_incidents: 1 },
  applications: [{ entity_id: "a1", application_name: "Claims", stage: "discovered" }],
  reviewTasks: [
    { task_id: "t1", title: "Intake review: Claims", application_name: "Claims", status: "open", assigned_to: "rev@x", due_at: "2026-09-01", escalation_status: "on_track", priority: "high" },
    { task_id: "t2", title: "Unassigned change review", application_name: "Claims", status: "open", assigned_to: null, assigned_role: "governance_reviewer", priority: "medium" },
  ],
  deploymentGates: [{ gate_id: "g1", application_name: "Claims", workflow_name: "triage", gate_status: "pending_review", required_reason: "missing linked prompt version" }],
  incidents: [{ incident_id: "i1", title: "PHI leak", application_name: "Claims", severity: "high", status: "open" }],
  risks: [{ finding_id: "r1", risk: "No guardrail", application_name: "Claims", status: "open", severity: "high" }],
  owners: [{ owner_assignment_id: "o1", subject_type: "application", subject_name: "Claims", application_name: "Claims", owner_role: "business_owner", status: "unassigned" }],
  decisions: [{ target_id: "t0", created_at: "2026-08-22", decision: "approve", target_type: "review_task", rationale: "fine", actor_ref: "gov@x" }],
  totals: {},
  partialErrors: [],
};

describe("Home", () => {
  it("is shaped by role: a reviewer sees their queue, not admin posture", () => {
    const reviewer = { ...base, user_ref: "rev@x", permissions: ["review.decide"] };
    expect(personaOf(reviewer as any)).toBe("decider");
    render(<Home user={reviewer as any} data={data} setupComplete={null} />);
    expect(screen.getByText("Assigned to you · 1")).toBeInTheDocument();
    expect(screen.getByText("Intake review: Claims")).toBeInTheDocument();
    expect(screen.getByText("Unassigned in your role · 1")).toBeInTheDocument();
    expect(screen.queryByText("Release gates to decide · 1")).not.toBeInTheDocument(); // no gate.decide
    expect(screen.queryByText("Organization posture")).not.toBeInTheDocument();
  });

  it("an administrator sees posture and setup nudge, but no decision work", () => {
    const admin = { ...base, permissions: ["user.manage", "owner.assign"] };
    expect(personaOf(admin as any)).toBe("admin");
    render(<Home user={admin as any} data={data} setupComplete={false} />);
    expect(screen.getByText("Organization posture")).toBeInTheDocument();
    expect(screen.getByText("Setup is not finished.")).toBeInTheDocument();
    expect(screen.getByText("Need an accountable owner · 1")).toBeInTheDocument();
    expect(screen.queryByText("Release gates to decide · 1")).not.toBeInTheDocument();
    expect(screen.getByText("Unregistered")).toBeInTheDocument();
  });

  it("a governance admin sees gates, incidents and high findings", () => {
    const gov = { ...base, user_ref: "gov@x", permissions: ["review.decide", "gate.decide", "incident.close", "risk.accept"] };
    render(<Home user={gov as any} data={data} setupComplete={null} />);
    expect(screen.getByText("Release gates to decide · 1")).toBeInTheDocument();
    expect(screen.getByText("Open incidents · 1")).toBeInTheDocument();
    expect(screen.getByText("High-severity findings · 1")).toBeInTheDocument();
    expect(screen.getByText("Recent decisions")).toBeInTheDocument();
  });

  it("a viewer with nothing to do is told why", () => {
    const viewer = { ...base, permissions: [] };
    render(<Home user={viewer as any} data={{ ...data, owners: [] }} setupComplete={null} />);
    expect(screen.getByText("You are clear.")).toBeInTheDocument();
    expect(screen.getAllByText(/read access/).length).toBeGreaterThan(0);
  });
});
