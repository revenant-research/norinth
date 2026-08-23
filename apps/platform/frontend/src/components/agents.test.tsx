import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { AgentsView, hasTrifecta } from "./agents";

const posture = {
  agents: [
    {
      agent_name: "claims-triage",
      application_name: "Claims",
      registered: true,
      run_count: 3,
      tools_used: ["lookup_claim"],
      owner_ref: "oa@acme.test",
      autonomy_level: 2,
      issues: [],
    },
    {
      agent_name: "rogue-bot",
      application_name: "Claims",
      registered: false,
      run_count: 1,
      tools_used: ["send_email"],
      issues: ["unregistered_agent"],
    },
    {
      agent_name: "autopilot",
      registered: true,
      run_count: 2,
      tools_used: ["browse", "delete_records"],
      owner_ref: "oa@acme.test",
      autonomy_level: 4,
      issues: ["unauthorized_tool", "agent_trifecta"],
      unauthorized_tools: ["delete_records"],
    },
  ],
  summary: { observed: 3, registered: 2, shadow: 1, with_issues: 2 },
};

const registry = {
  agents: [
    {
      agent_id: "id-1",
      agent_name: "claims-triage",
      status: "active",
      owner_ref: "oa@acme.test",
      autonomy_level: 2,
      allowed_tools: ["lookup_claim"],
      processes_untrusted_input: true,
      accesses_sensitive_data: true,
      can_act_externally: false,
      human_checkpoint: true,
    },
  ],
  autonomy_levels: { "0": "tool-assisted", "1": "conditional", "2": "supervised", "3": "delegated", "4": "fully autonomous" },
};

describe("hasTrifecta", () => {
  it("is true only when all three legs are present", () => {
    expect(hasTrifecta({ processes_untrusted_input: true, accesses_sensitive_data: true, can_act_externally: true })).toBe(true);
    expect(hasTrifecta({ processes_untrusted_input: true, accesses_sensitive_data: true, can_act_externally: false })).toBe(false);
  });
});

describe("AgentsView", () => {
  beforeEach(() => {
    vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      if (path === "/api/agents/posture") return posture as any;
      if (path === "/api/agent-registry") return registry as any;
      throw new Error(`unexpected ${path}`);
    });
  });

  it("renders posture summary and OWASP-mapped issue badges", async () => {
    render(<AgentsView scope={{}} canRegister={false} canRetire={false} />);
    await waitFor(() => expect(screen.getAllByTestId("agent-card")).toHaveLength(3));

    // Shadow agent flagged with its OWASP reference.
    expect(screen.getByText("Shadow agent (unregistered)")).toBeInTheDocument();
    expect(screen.getByText("ASI10 Rogue agents")).toBeInTheDocument();

    // Unauthorized tool lists the offending tool inside the issue badge; trifecta is shown.
    const toolIssue = screen.getByText("Tool outside allow-list").closest("li");
    expect(toolIssue).toHaveTextContent("delete_records");
    expect(screen.getByText("Lethal trifecta, no human checkpoint")).toBeInTheDocument();

    // Clean agent says so.
    expect(screen.getByText("No agentic-governance issues.")).toBeInTheDocument();

    // Registration form hidden without config.write.
    expect(screen.queryByRole("form", { name: "Register an agent" })).not.toBeInTheDocument();
  });

  it("warns inline when the registration profile forms the lethal trifecta", async () => {
    const user = userEvent.setup();
    render(<AgentsView scope={{}} canRegister={true} canRetire={true} />);
    await waitFor(() => expect(screen.getByRole("form", { name: "Register an agent" })).toBeInTheDocument());

    await user.click(screen.getByLabelText(/Processes untrusted input/));
    await user.click(screen.getByLabelText(/Accesses sensitive/));
    await user.click(screen.getByLabelText(/Can change state/));
    expect(screen.queryByTestId("trifecta-warning")).not.toBeInTheDocument(); // checkpoint still on

    await user.click(screen.getByLabelText(/A human checkpoint/)); // turn it off
    expect(screen.getByTestId("trifecta-warning")).toBeInTheDocument();
  });

  it("submits a registration with parsed allow-list and reloads", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({} as any);
    render(<AgentsView scope={{}} canRegister={true} canRetire={false} />);
    await waitFor(() => expect(screen.getByRole("form", { name: "Register an agent" })).toBeInTheDocument());

    await user.type(screen.getByLabelText("Agent name"), "helper");
    await user.type(screen.getByLabelText("Accountable owner"), "owner@acme.test");
    await user.type(screen.getByLabelText(/Allowed tools/), "search, summarize ,");
    await user.click(screen.getByRole("button", { name: "Register agent" }));

    await waitFor(() => expect(post).toHaveBeenCalled());
    const [path, body] = post.mock.calls[0];
    expect(path).toBe("/api/agent-registry");
    expect((body as any).allowed_tools).toEqual(["search", "summarize"]);
    expect((body as any).agent_name).toBe("helper");
  });
});
