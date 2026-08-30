// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GettingStarted } from "./guide";

// the collector snippet has to name the route the platform actually serves.
// otlphttp treats `endpoint` as a base and appends /v1/traces to it, so an
// endpoint of <host>/v1/otel posts to /v1/otel/v1/traces, which is a 404. the
// per-signal `traces_endpoint` is sent verbatim
describe("OpenTelemetry collector snippet", () => {
  it("points the collector at the route the platform serves", async () => {
    vi.spyOn(await import("../api"), "getJson").mockResolvedValue({
      steps: [], completed: 0, required: 0, complete: false, ingestion_key_hint: null,
    } as never);

    render(<GettingStarted />);
    const snippet = await screen.findByText(/otlphttp\/norinth/);
    const text = snippet.textContent || "";

    expect(text).toContain("traces_endpoint:");
    expect(text).toContain("/v1/otel/traces");
    // the base-endpoint form silently resolves to /v1/otel/v1/traces
    expect(text).not.toMatch(/\bendpoint:\s*\S+\/v1\/otel\s*$/m);
  });
});
