// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import * as confirmModule from "./confirm";
import {
  type PolicyDoc,
  PolicyView,
  describeTier,
  localIssues,
  stageListWith,
  unstaffedRoles,
  updateGateRule,
  updateTier,
} from "./policy";

const RISK_TIERS = ["limited", "elevated", "high"];

function baseDoc(): PolicyDoc {
  return {
    schema: "governance-policy/v1",
    intake: {
      tiers: {
        limited: { stages: [{ role: "governance_reviewer" }], mode: "sequence" },
        elevated: { stages: [{ role: "governance_reviewer" }], mode: "sequence" },
        high: {
          stages: [
            { role: "governance_reviewer", label: "Security review" },
            { role: "risk_owner", label: "Risk acceptance" },
          ],
          mode: "sequence",
          recertify_days: 180,
        },
      },
      fields: [],
    },
    gates: { environments: { "*": { require_attested_evals: false, max_open_material_changes: 0 } } },
    vendors: { stages: [{ role: "governance_reviewer" }], recertify_days: 365 },
  };
}

const META = {
  policy: { tenant_id: "acme", version: 3, body: baseDoc(), body_hash: "a".repeat(64), activated_at: "2026-08-30 10:00:00", source: "tenant" },
  decision_roles: ["governance_admin", "governance_reviewer", "risk_owner"],
  risk_tiers: RISK_TIERS,
  limits: { recertify_days_floor: 30, max_open_material_changes_ceiling: 0, max_stages: 10, max_fields: 20 },
};

const LIVE = {
  intake: [
    { intake_id: "i1", risk_tier: "high", status: "approved" },
    { intake_id: "i2", risk_tier: "high", status: "submitted" },
    { intake_id: "i3", risk_tier: "limited", status: "retired" },
  ],
};

const STAGES = {
  approval_stages: [
    { stage_id: "s1", subject_id: "t1", status: "open", policy_tenant: "acme", policy_version: 3 },
    { stage_id: "s2", subject_id: "t1", status: "pending", policy_tenant: "acme", policy_version: 3 },
    { stage_id: "s3", subject_id: "t2", status: "approved", policy_tenant: "acme", policy_version: 2 },
  ],
};

// nobody holds risk_owner: the high tier's second step cannot complete
const STAFFING = {
  role_assignments: [
    { role: "governance_reviewer", status: "active" },
    { role: "governance_admin", status: "active" },
    { role: "risk_owner", status: "revoked" },
  ],
};

// two systems discovered in telemetry but never submitted: the estate the
// policy does not govern yet
const APPLICATIONS = {
  applications: [
    { entity_id: "a1", application_name: "Claims Triage Assistant", stage: "in_review" },
    { entity_id: "a2", application_name: "Radiology Notes", stage: "discovered" },
    { entity_id: "a3", application_name: "Shadow Chatbot", stage: "discovered" },
  ],
};

function mockLoads() {
  vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
    if (path === "/api/governance-policy") return META as any;
    if (path === "/api/governance-policy/versions") return { versions: [] } as any;
    if (path === "/api/intake") return LIVE as any;
    if (path === "/api/applications") return APPLICATIONS as any;
    if (path.startsWith("/api/approval-stages")) return STAGES as any;
    if (path === "/api/org/role-assignments") return STAFFING as any;
    if (path.startsWith("/api/governance-policy/diff")) return { from: "in force", to: "v4", diff: ["changed intake.tiers.high.stages"] } as any;
    throw new Error(`unexpected ${path}`);
  });
}

describe("document helpers", () => {
  it("edits are immutable and stage lists reorder cleanly", () => {
    const doc = baseDoc();
    const withStage = updateTier(doc, "high", {
      stages: stageListWith(doc.intake!.tiers!.high.stages, { add: true }, "governance_reviewer"),
    });
    expect(doc.intake!.tiers!.high.stages).toHaveLength(2); // original untouched
    expect(withStage.intake!.tiers!.high.stages).toHaveLength(3);

    const reordered = stageListWith(
      [{ role: "governance_reviewer" }, { role: "risk_owner" }],
      { moveUp: 1 },
      "governance_reviewer",
    );
    expect(reordered.map((stage) => stage.role)).toEqual(["risk_owner", "governance_reviewer"]);

    const withoutRule = updateGateRule(updateGateRule(doc, "staging", { require_attested_evals: true }), "staging", null);
    expect(withoutRule.gates!.environments!.staging).toBeUndefined();
  });

  it("reads a tier rule back as a plain sentence", () => {
    expect(describeTier("limited", { stages: [{ role: "governance_reviewer" }] })).toBe(
      "A limited-risk system needs one approval by a governance reviewer.",
    );
    expect(
      describeTier("high", {
        stages: [{ role: "governance_reviewer", label: "Security review" }, { role: "risk_owner" }],
        mode: "sequence",
        recertify_days: 180,
      }),
    ).toBe("A high-risk system needs 2 approvals by different people, in order: security review, then a risk owner, recertified every 180 days.");
  });

  it("names roles nobody holds and skips the check when staffing is unreadable", () => {
    const stages = [{ role: "governance_reviewer" }, { role: "risk_owner" }];
    expect(unstaffedRoles(stages, new Set(["governance_reviewer"]))).toEqual(["risk_owner"]);
    expect(unstaffedRoles(stages, null)).toEqual([]);
  });

  it("flags empty paths and malformed field keys before the server does", () => {
    const doc = baseDoc();
    doc.intake!.tiers!.high.stages = [];
    doc.intake!.fields = [{ key: "Bad Key" }, { key: "dpia_ref" }, { key: "dpia_ref" }];
    const issues = localIssues(doc, RISK_TIERS);
    expect(issues.some((issue) => issue.includes("high"))).toBe(true);
    expect(issues.some((issue) => issue.includes("lowercase identifiers"))).toBe(true);
    expect(issues.some((issue) => issue.includes("duplicate key"))).toBe(true);
  });
});

describe("PolicyView", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.location.hash = "";
    mockLoads();
  });

  it("shows each path with live counts, sentences, and staffing gaps", async () => {
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("policy-toolbar")).toBeInTheDocument());

    // what is in force, wired to live state
    expect(screen.getByTestId("policy-toolbar")).toHaveTextContent("Your policy v3 is in force");
    expect(screen.getByTestId("policy-toolbar")).toHaveTextContent("Governing 2 systems");
    expect(screen.getByTestId("policy-toolbar")).toHaveTextContent("1 review in flight");
    // discovery is the source of truth: systems seen in telemetry that nobody
    // has submitted are called out as ungoverned, linking to the inventory
    expect(screen.getByTestId("policy-toolbar")).toHaveTextContent(
      "2 systems seen running in production are not under this policy yet",
    );
    expect(screen.getByRole("link", { name: "See the inventory." })).toBeInTheDocument();

    // the high tier: live count, its two steps as an editable pipeline, the sentence
    const high = screen.getByTestId("tier-card-high");
    expect(high).toHaveTextContent("2 systems today");
    expect(screen.getByDisplayValue("Security review")).toBeInTheDocument();
    expect(screen.getByLabelText("high tier step 2 decided by")).toHaveValue("risk_owner");
    expect(high).toHaveTextContent("then");
    expect(high).toHaveTextContent("A high-risk system needs 2 approvals by different people, in order");

    // nobody holds risk_owner: the path warns and links to staffing
    expect(high).toHaveTextContent("Nobody holds risk owner");
    expect(screen.getAllByRole("link", { name: /People & access/ }).length).toBeGreaterThan(0);

    // no JSON anywhere on the working surface
    expect(screen.queryByRole("button", { name: /JSON/ })).not.toBeInTheDocument();
  });

  it("splits the builder into one concern per view, each with plain guidance", async () => {
    const user = userEvent.setup();
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("policy-paths")).toBeInTheDocument());

    // paths is the default view, opening with what a path is and what to do
    expect(screen.getByTestId("tab-guide")).toHaveTextContent(
      "An approval path is the list of people who must sign off before an AI system is approved",
    );
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("What to do");
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("Pick who decides each step");

    // the other views are a click away and edits carry across because the
    // document is one unit; each view opens with its own guidance
    expect(screen.queryByRole("button", { name: "Add question" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("link", { name: "Intake form" }));
    expect(screen.getByRole("button", { name: "Add question" })).toBeInTheDocument();
    expect(screen.queryByTestId("policy-paths")).not.toBeInTheDocument();
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("extra questions people answer when they submit a system");
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("Never ask for patient data");

    await user.click(screen.getByRole("link", { name: "Release gates" }));
    expect(screen.getByTestId("gate-rule-*")).toBeInTheDocument();
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("stops a deployment from shipping until the proof is there");

    // history holds the versions and the raw document for auditors
    await user.click(screen.getByRole("link", { name: /History/ }));
    expect(screen.getByText("Raw policy document (for auditors and the API)")).toBeInTheDocument();
    expect(screen.getByTestId("tab-guide")).toHaveTextContent("A review keeps the version it started under");

    // the in-force header and its actions persist across every view
    expect(screen.getByTestId("policy-toolbar")).toHaveTextContent("Your policy v3 is in force");
  });

  it("editing the pipeline directly enables the one primary action", async () => {
    const user = userEvent.setup();
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("tier-card-limited")).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: "Review & put in force" })).not.toBeInTheDocument();
    const limited = screen.getByTestId("tier-card-limited");
    await user.click(limited.querySelector(".pipeline-add") as HTMLElement);

    expect(screen.getByText("unsaved changes")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review & put in force" })).toBeEnabled();
  });

  it("review & put in force drafts, shows the changes, and activates on confirm", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({ policy: { version: 4 } } as any);
    const confirmSpy = vi.spyOn(confirmModule, "confirm").mockResolvedValue(true);
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("tier-card-high")).toBeInTheDocument());

    await user.click(screen.getByTestId("tier-card-high").querySelector(".pipeline-add") as HTMLElement);
    await user.click(screen.getByRole("button", { name: "Review & put in force" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/governance-policy/versions/4/activate", {}));
    expect(post.mock.calls[0][0]).toBe("/api/governance-policy/draft");
    expect((post.mock.calls[0][1] as any).body.intake.tiers.high.stages).toHaveLength(3);
    const dialog = confirmSpy.mock.calls[0][0];
    expect(dialog.body).toContain("changed intake.tiers.high.stages");
    expect(dialog.body).toContain("reviews already in flight keep the rules they started under");
  });

  it("declining the confirmation keeps the draft in history without activating", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({ policy: { version: 4 } } as any);
    vi.spyOn(confirmModule, "confirm").mockResolvedValue(false);
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("tier-card-high")).toBeInTheDocument());

    await user.click(screen.getByTestId("tier-card-high").querySelector(".pipeline-add") as HTMLElement);
    await user.click(screen.getByRole("button", { name: "Review & put in force" }));

    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post.mock.calls[0][0]).toBe("/api/governance-policy/draft");
  });

  it("surfaces local problems and blocks the primary action until fixed", async () => {
    const user = userEvent.setup();
    render(<PolicyView />);
    await waitFor(() => expect(screen.getByTestId("policy-toolbar")).toBeInTheDocument());

    await user.click(screen.getByRole("link", { name: "Intake form" }));
    await user.click(screen.getByRole("button", { name: "Add question" }));
    await user.type(screen.getByLabelText("Field 1 key"), "Bad Key");
    expect(screen.getByTestId("policy-problems")).toHaveTextContent("lowercase identifiers");
    expect(screen.getByRole("button", { name: "Review & put in force" })).toBeDisabled();
  });
});
