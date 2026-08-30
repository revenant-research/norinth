// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { AuditLog } from "./admin";

function entries(offset: number, count: number) {
  return Array.from({ length: count }, (_, i) => ({
    id: offset + i + 1,
    action: `action.${offset + i + 1}`,
    tenant_id: "acme",
    actor_ref: "u1",
    created_at: "2026-08-22T00:00:00Z",
  }));
}

afterEach(() => vi.restoreAllMocks());

describe("AuditLog", () => {
  it("pages through the server-side audit trail", async () => {
    const total = 120;
    const spy = vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      const params = new URL(path, "http://x").searchParams;
      const offset = Number(params.get("offset") || 0);
      const limit = Number(params.get("limit") || 50);
      const count = Math.max(0, Math.min(limit, total - offset));
      return {
        audit_logs: entries(offset, count),
        page: { offset, limit, total, has_more: offset + count < total },
      };
    });

    render(<AuditLog />);
    await waitFor(() => expect(screen.getByText("action.1")).toBeInTheDocument());
    expect(screen.getByRole("status", { name: "" })).toHaveTextContent("Page 1 of 3 · 120 entries");
    expect(screen.getByRole("button", { name: "Newer" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(screen.getByText("action.51")).toBeInTheDocument());
    expect(screen.queryByText("action.1")).not.toBeInTheDocument();
    expect(spy).toHaveBeenLastCalledWith(expect.stringContaining("offset=50"));

    await userEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(screen.getByText("action.101")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Older" })).toBeDisabled();
  });

  it("resets to the first page when filters change", async () => {
    const spy = vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      const offset = Number(new URL(path, "http://x").searchParams.get("offset") || 0);
      return { audit_logs: entries(offset, 50), page: { offset, limit: 50, total: 200, has_more: true } };
    });
    render(<AuditLog />);
    await waitFor(() => expect(screen.getByText("action.1")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(spy).toHaveBeenLastCalledWith(expect.stringContaining("offset=50")));

    await userEvent.type(screen.getByLabelText("Action"), "role.assign");
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(spy).toHaveBeenLastCalledWith(expect.stringContaining("offset=0")));
    expect(spy).toHaveBeenLastCalledWith(expect.stringContaining("action=role.assign"));
  });
});
