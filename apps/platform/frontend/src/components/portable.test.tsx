// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  createPortableClient,
  safePortableLink,
  type PortableRecord,
  type SystemWorkspace,
} from "../portable";
import { PortableSystemWorkspace, PortableSystemsView } from "./portable";
import { SystemHubHeader } from "./systemHub";
import { ConfirmHost } from "./confirm";
import { runAxe, formatViolations } from "../test/axe";

const system: PortableRecord = {
  record_id: "system-1",
  tenant_id: "documents",
  kind: "system",
  project: "documents",
  environment: "prod",
  integration_id: "runner-1",
  state: "approved",
  created_by: "integration:runner-1",
  created_at: "2026-09-30T12:00:00Z",
  body: {
    display_name: "Document processing",
    resource_type: "job",
    purpose: "Process documents",
  },
};
const revision: PortableRecord = {
  ...system,
  record_id: "revision-1",
  kind: "revision",
  created_by: "builder@test",
  state: "approved",
  body: {
    manifest: {
      revision: "r1",
      models: ["provider/model"],
      tools: [],
      autonomy_level: 0,
    },
    manifest_digest: "sha256:abc",
  },
};
const workspace: SystemWorkspace = {
  system,
  integration: {
    ...system,
    record_id: "runner-1",
    state: "active",
    body: { name: "Independent job runner", capabilities: [] },
  },
  revisions: [revision],
  policies: [],
  authorizations: [],
  receipts: [],
  decisions: [],
  observations: [],
  verifications: [],
  packs: [],
  active_policy: null,
  eligibility: {
    "revision-1": {
      outcome: "indeterminate",
      reasons: ["stale_evidence:quality"],
      checked_at: "2026-09-30T12:00:00Z",
      policy_id: null,
      evidence_ids: [],
      enforcement: "executor_required",
    },
  },
};
function hostClient(value = workspace) {
  const transport = vi.fn().mockResolvedValue(value);
  return { client: createPortableClient(transport), transport };
}

describe("Portable workspace with an independent host", () => {
  it("keeps historic approval separate from current eligibility and enforcement", async () => {
    const { client } = hostClient();
    const { container } = render(
      <PortableSystemWorkspace
        systemId="system-1"
        client={client}
        user={{ user_ref: "reader@test", permissions: [] }}
        resolveLink={() => "https://job-runner.example.test/jobs/42"}
      />,
    );
    await screen.findByText(/evidence for quality has expired/);
    expect(screen.getAllByText("Approved")).toHaveLength(2);
    expect(screen.getByText("Cannot establish permission")).toBeInTheDocument();
    expect(
      screen.getByText(/has not verified that the executor/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByRole("link", { name: "Open in source platform" })[0],
    ).toHaveAttribute("href", "https://job-runner.example.test/jobs/42");
    expect(
      screen.queryByRole("button", { name: "Approve this revision" }),
    ).not.toBeInTheDocument();
    const accessibility = await runAxe(container);
    expect(accessibility.violations, formatViolations(accessibility)).toEqual(
      [],
    );
  });

  it("records an exact authorized decision only after a rationale and confirmation", async () => {
    const pending = { ...revision, state: "pending_review" };
    const value = {
      ...workspace,
      revisions: [pending],
      eligibility: {
        "revision-1": {
          ...workspace.eligibility["revision-1"],
          outcome: "requires_review",
          reasons: ["revision_requires_review"],
        },
      },
    };
    const { client, transport } = hostClient(value);
    const user = userEvent.setup();
    render(
      <>
        <PortableSystemWorkspace
          systemId="system-1"
          client={client}
          user={{ user_ref: "reviewer@test", permissions: ["gate.decide"] }}
        />
        <ConfirmHost />
      </>,
    );
    const button = await screen.findByRole("button", {
      name: "Approve this revision",
    });
    expect(button).toBeDisabled();
    await user.type(
      screen.getByLabelText("Decision rationale"),
      "Quality evidence and operating limits have been reviewed.",
    );
    await user.click(button);
    expect(transport).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Record decision" }));
    await waitFor(() =>
      expect(transport).toHaveBeenCalledWith(
        "/api/portable/records/revision-1/approve_revision",
        "POST",
        {
          rationale:
            "Quality evidence and operating limits have been reviewed.",
        },
      ),
    );
  });

  it("does not offer self-approval or invalid evidence approval", async () => {
    const value = {
      ...workspace,
      revisions: [{ ...revision, state: "pending_review" }],
    };
    const { client } = hostClient(value);
    render(
      <PortableSystemWorkspace
        systemId="system-1"
        client={client}
        user={{ user_ref: "builder@test", permissions: ["gate.decide"] }}
        resolveLink={() => "javascript:alert(1)"}
      />,
    );
    await screen.findByText("Revision needs review");
    expect(
      screen.queryByRole("button", { name: "Approve this revision" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Open in source platform" }),
    ).not.toBeInTheDocument();
  });

  it("loads the standalone planned inventory without relying on telemetry", async () => {
    const transport = vi
      .fn()
      .mockResolvedValue({
        systems: [{ ...system, state: "planned" }],
        has_more: false,
      });
    const client = createPortableClient(transport);
    render(
      <PortableSystemsView
        client={client}
        user={{
          user_ref: "reader",
          permissions: [],
          display_name: "Reader",
          email: null,
          tenant_id: "documents",
          platform_role: null,
          must_change_password: false,
          is_super_admin: false,
        }}
      />,
    );
    await screen.findByRole("button", { name: "Open Document processing" });
    expect(transport.mock.calls[0][0]).toBe(
      "/api/portable/systems?offset=0&limit=50",
    );
    expect(screen.getByText("Purpose needs review")).toBeInTheDocument();
  });

  it("rejects executable and relative host links", () => {
    expect(safePortableLink("javascript:alert(1)")).toBeUndefined();
    expect(safePortableLink("data:text/html,foo")).toBeUndefined();
    expect(safePortableLink("/relative/path")).toBeUndefined();
    expect(safePortableLink("https://job-runner.example.test/jobs/42")).toBe(
      "https://job-runner.example.test/jobs/42",
    );
  });
});

describe("Legacy readiness remains truthful", () => {
  it.each(["retired", "in_review", "rejected"])(
    "does not show a clear release state for a %s system",
    (stage) => {
      render(<SystemHubHeader detail={{ application: { stage } }} />);
      expect(
        screen.queryByText("Nothing is blocking this system."),
      ).not.toBeInTheDocument();
      expect(
        screen.getByText("What is blocking this system"),
      ).toBeInTheDocument();
    },
  );
  it("counts pending gates and findings requiring mitigation", () => {
    render(
      <SystemHubHeader
        detail={{
          application: { stage: "approved" },
          deployment_gates: [{ gate_status: "pending_review" }],
          risks: [{ status: "mitigation_required" }],
        }}
      />,
    );
    expect(
      screen.getByText(/release gate awaiting review/),
    ).toBeInTheDocument();
    expect(
      screen.queryByText("Nothing is blocking this system."),
    ).not.toBeInTheDocument();
  });
});
