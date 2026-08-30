// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, waitFor, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "./api";
import { AuditLog } from "./components/admin";
import { AgentsView } from "./components/agents";
import { Sidebar, SkipLink } from "./components/shell";
import { RecordList } from "./components/ui";
import { formatViolations, runAxe } from "./test/axe";

afterEach(() => vi.restoreAllMocks());

async function expectAccessible(container: Element) {
  const results = await runAxe(container);
  expect(results.violations, formatViolations(results)).toEqual([]);
}

describe("accessibility (axe-core)", () => {
  it("shell: skip link + labelled navigation", async () => {
    const { container } = render(
      <>
        <SkipLink />
        <Sidebar tagline="Workspace" routes={[{ id: "overview", label: "Overview" }, { id: "risk", label: "Risk" }]} active="risk" />
        <main id="main-content">
          <h1>Risk</h1>
        </main>
      </>,
    );
    await expectAccessible(container);
  });

  it("record list with paging footer", async () => {
    const { container } = render(
      <main>
        <h1>List</h1>
        <RecordList empty="" pageSize={2} total={50}>
          {[1, 2, 3, 4].map((i) => (
            <article className="record-card" key={i}>
              Record {i}
            </article>
          ))}
        </RecordList>
      </main>,
    );
    await expectAccessible(container);
  });

  it("audit log with filters and pager", async () => {
    vi.spyOn(api, "getJson").mockResolvedValue({
      audit_logs: [{ id: 1, action: "auth.login", tenant_id: "acme", actor_ref: "u1", created_at: "2026-08-22T00:00:00Z" }],
      page: { offset: 0, limit: 50, total: 120, has_more: true },
    });
    const { container } = render(
      <main>
        <h1>Audit</h1>
        <AuditLog superAdmin />
      </main>,
    );
    await waitFor(() => expect(screen.getByText("auth.login")).toBeInTheDocument());
    await expectAccessible(container);
  });

  it("agents view with registry form", async () => {
    vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      if (path.includes("posture")) return { agents: [], summary: { total: 0, unregistered: 0, trifecta: 0, high_autonomy: 0 } };
      return { agents: [] };
    });
    const { container } = render(
      <main>
        <h1>Agents</h1>
        <AgentsView scope={{ tenantId: "acme", project: "", environment: "" }} canRegister canRetire />
      </main>,
    );
    await waitFor(() => expect(screen.getByRole("form", { name: "Register an agent" })).toBeInTheDocument());
    await expectAccessible(container);
  });
});
