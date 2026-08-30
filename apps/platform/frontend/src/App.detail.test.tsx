// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "./api";
import { DetailRoute } from "./App";

const scope = { tenantId: "acme", project: "", environment: "" };
const mutate = vi.fn(async () => undefined);

const gate = {
  deployment_gate: {
    gate_id: "g1",
    application_name: "Claims",
    workflow_name: "triage",
    gate_status: "pending_review",
    review_status: "open",
    deployment_status: "pending",
    risk_count: 0,
    missing_control_count: 0,
    evals: [],
  },
  deployment: {},
  risks: [],
  controls: [],
  review_tasks: [],
  incidents: [],
  evals: [],
};
const incident = {
  incident: {
    incident_id: "i1",
    title: "PHI leaked in summary",
    application_name: "Claims",
    workflow_name: "triage",
    severity: "high",
    status: "open",
  },
  trace: null,
  risks: [],
  review_tasks: [],
  decisions: [],
};

afterEach(() => vi.restoreAllMocks());

describe("DetailRoute", () => {
  it("does not hand a stale payload to the next detail view when the route kind changes", async () => {
    // route kind change must not render the previous payload as the new kind
    let resolveIncident: (value: unknown) => void = () => undefined;
    vi.spyOn(api, "loadDetail").mockImplementation(async (kind: api.DetailKind) => {
      if (kind === "gate") return gate;
      return new Promise((resolve) => {
        resolveIncident = resolve;
      });
    });
    vi.spyOn(api, "loadGraphNeighborhood").mockResolvedValue({});
    const onError = vi.fn();
    window.addEventListener("error", onError);

    const { rerender } = render(<DetailRoute kind="gate" id="g1" scope={scope} mutate={mutate} />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "Claims release gate" })).toBeInTheDocument());

    rerender(<DetailRoute kind="incident" id="i1" scope={scope} mutate={mutate} />);
    // while the incident loads, the gate payload must not render as an incident
    expect(screen.getByRole("status")).toHaveTextContent("Loading the selected record.");
    expect(screen.queryByRole("heading", { name: "Claims release gate" })).not.toBeInTheDocument();

    resolveIncident(incident);
    await waitFor(() => expect(screen.getByRole("heading", { name: "PHI leaked in summary" })).toBeInTheDocument());
    expect(onError).not.toHaveBeenCalled();
    window.removeEventListener("error", onError);
  });

  it("renders an empty state instead of throwing when the payload lacks its record", async () => {
    vi.spyOn(api, "loadDetail").mockResolvedValue({ risks: [] });
    render(<DetailRoute kind="incident" id="missing" scope={scope} mutate={mutate} />);
    await waitFor(() => expect(screen.getByText("The requested record is no longer available.")).toBeInTheDocument());
  });
});
