// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, loadDashboardData, totalOf } from "./api";

const scope = { tenantId: "acme", project: "", environment: "" };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

afterEach(() => vi.unstubAllGlobals());

describe("loadDashboardData", () => {
  it("captures server totals and degrades per endpoint instead of failing the whole load", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.startsWith("/api/risk-register")) {
          return jsonResponse({ detail: "risk engine unavailable" }, 503);
        }
        if (url.startsWith("/api/events") || url.startsWith("/api/model-calls")) {
          return jsonResponse({
            model_calls: [{ model: "gpt" }],
            events: [],
            page: { offset: 0, limit: 200, total: 9876, has_more: true },
          });
        }
        if (url.startsWith("/api/summary")) return jsonResponse({ applications: 1 });
        // generic list: return every plausible key empty with a page block
        return jsonResponse({
          applications: [], workflows: [], models: [], agents: [], retrievals: [], tools: [], guardrails: [],
          evals: [], controls: [], review_tasks: [], prompt_templates: [], deployments: [],
          deployment_gates: [], incidents: [], owners: [], decisions: [], exceptions: [], traces: [], intake: [],
          page: { offset: 0, limit: 200, total: 0, has_more: false },
        });
      }),
    );

    const data = await loadDashboardData(scope);
    expect(data.modelCalls).toEqual([{ model: "gpt" }]);
    expect(data.totals.modelCalls).toBe(9876);
    expect(totalOf(data, "modelCalls", data.modelCalls)).toBe(9876);
    // lists without page metadata fall back to the loaded length
    expect(totalOf({ totals: {} }, "risks", [1, 2, 3] as unknown[])).toBe(3);
    // failed endpoint is reported, not fatal
    expect(data.risks).toEqual([]);
    expect(data.partialErrors).toEqual([{ key: "risks", message: "risk engine unavailable" }]);
    expect(data.summary).toEqual({ applications: 1 });
  });

  it("still propagates session loss so the shell can sign the user out", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: "Not authenticated" }, 401)),
    );
    await expect(loadDashboardData(scope)).rejects.toBeInstanceOf(ApiError);
  });
});
