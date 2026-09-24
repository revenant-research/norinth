// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ControlCoverage } from "../App";
import { updateEvidence, updateGateRule } from "./policy";

const coverage = {
  basis_event_types: ["model.call"],
  window_days: 7,
  basis_traces: 4,
  covered_traces: 1,
  coverage_pct: 25,
  last_evidence_at: "2026-09-20 10:00:00",
  stale_after_days: 30,
  stale: false,
};

describe("control coverage", () => {
  it("states the share of recent traffic the evidence covers", () => {
    render(<ControlCoverage coverage={coverage} passing />);
    expect(screen.getByTestId("control-coverage")).toHaveTextContent(
      "Covers 25% of 4 model.call traces in the last 7 days (1 with evidence).",
    );
    expect(screen.queryByText("stale")).not.toBeInTheDocument();
  });

  it("says when there was no traffic to cover", () => {
    render(<ControlCoverage coverage={{ ...coverage, basis_traces: 0, covered_traces: 0, coverage_pct: null }} passing />);
    expect(screen.getByTestId("control-coverage")).toHaveTextContent("No model.call traffic in the last 7 days.");
  });

  it("marks a passing control with old evidence as stale, and only a passing one", () => {
    const { rerender } = render(<ControlCoverage coverage={{ ...coverage, stale: true }} passing />);
    expect(screen.getByText("stale")).toBeInTheDocument();
    rerender(<ControlCoverage coverage={{ ...coverage, stale: true }} passing={false} />);
    expect(screen.queryByText("stale")).not.toBeInTheDocument();
  });
});

describe("evidence policy helpers", () => {
  const doc = { schema: "governance-policy/v1" };

  it("sets and clears evidence settings without leaving empty sections", () => {
    const set = updateEvidence(doc, { stale_after_days: 14 });
    expect(set.evidence).toEqual({ stale_after_days: 14 });
    expect(doc).toEqual({ schema: "governance-policy/v1" }); // original untouched
    const cleared = updateEvidence(set, { stale_after_days: undefined });
    expect(cleared.evidence).toBeUndefined();
  });

  it("keeps other gate settings when the minimum coverage changes", () => {
    const attested = updateGateRule(doc, "prod", { require_attested_evals: true });
    const withMinimum = updateGateRule(attested, "prod", { min_control_coverage: 90 });
    expect(withMinimum.gates?.environments?.prod).toEqual({ require_attested_evals: true, min_control_coverage: 90 });
  });
});
