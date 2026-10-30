// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { VendorsView, daysUntil, splitList } from "./vendors";

const PAYLOAD = {
  vendors: [
    {
      vendor_id: "v1",
      name: "OpenAI",
      status: "under_review",
      providers: ["openai"],
      approved_models: ["gpt-4o"],
      review_round: 1,
      reviewed_at: null,
      evidence: [
        {
          reference_id: "e1",
          kind: "baa",
          kind_label: "Business associate agreement",
          name: "BAA 2026",
          identifier: "BAA-77",
          issued_at: "2026-01-01",
          expires_at: "2099-01-01",
          document_hash: null,
          status: "current",
        },
      ],
      evidence_expired: false,
      stages: [
        {
          stage_id: "s0",
          stage_index: 0,
          required_role: "governance_reviewer",
          label: null,
          mode: "sequence",
          status: "open",
          policy_tenant: "",
          policy_version: 1,
        },
      ],
    },
    {
      vendor_id: "v2",
      name: "Legacy LLM Co",
      status: "recertify_due",
      providers: ["legacyllm"],
      approved_models: null,
      review_round: 3,
      reviewed_at: "2025-01-01 00:00:00",
      evidence: [
        {
          reference_id: "e2",
          kind: "soc2_type2",
          kind_label: "SOC 2 Type II report",
          name: "SOC 2 2024",
          identifier: null,
          issued_at: "2024-01-01",
          expires_at: "2025-01-01",
          document_hash: null,
          status: "expired",
        },
      ],
      evidence_expired: true,
      stages: [],
    },
  ],
  coverage: {
    providers: [
      { provider: "openai", models: ["gpt-4o"], applications: ["Claims"], vendor: "OpenAI", vendor_status: "under_review", covered: false, disallowed_models: [] },
      { provider: "mistral", models: ["mistral-large"], applications: ["Claims"], vendor: null, vendor_status: null, covered: false, disallowed_models: [] },
    ],
    summary: { observed_providers: 2, covered: 0, uncovered: 2, registered_vendors: 2 },
  },
  policy: { stages: [{ role: "governance_reviewer" }], recertify_days: 365 },
  evidence_kinds: { baa: "Business associate agreement", soc2_type2: "SOC 2 Type II report" },
};

describe("splitList", () => {
  it("splits comma lists and drops blanks", () => {
    expect(splitList(" openai, azure_openai ,,")).toEqual(["openai", "azure_openai"]);
  });
});

describe("VendorsView", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "getJson").mockResolvedValue(PAYLOAD as any);
  });

  it("shows observed providers, coverage, review stages and lapsed approvals", async () => {
    render(<VendorsView canManage={true} canRetire={true} />);
    await waitFor(() => expect(screen.getAllByTestId("provider-card")).toHaveLength(2));

    // an unregistered provider offers a one-click registration prefill
    const mistral = screen.getAllByTestId("provider-card")[1];
    expect(mistral).toHaveTextContent("unreviewed");
    expect(screen.getByRole("button", { name: "Register mistral as a vendor" })).toBeInTheDocument();

    // an under-review vendor renders its stage checklist and decision panel
    expect(screen.getByTestId("stage-checklist")).toBeInTheDocument();
    expect(screen.getByTestId("stage-decision-panel")).toBeInTheDocument();

    // a lapsed approval explains itself and offers re-review
    const lapsed = screen.getAllByTestId("vendor-card")[1];
    expect(lapsed).toHaveTextContent("recertify_due");
    expect(lapsed).toHaveTextContent("Approval lapsed");
    expect(screen.getByRole("button", { name: "Re-review" })).toBeInTheDocument();
  });

  it("registers a vendor with parsed provider and model lists", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({} as any);
    render(<VendorsView canManage={true} canRetire={false} />);
    await waitFor(() => expect(screen.getByRole("form", { name: "Register a vendor" })).toBeInTheDocument());

    await user.type(screen.getByLabelText("Vendor name"), "Anthropic");
    await user.type(screen.getByLabelText(/Providers/), "anthropic, bedrock_anthropic");
    await user.type(screen.getByLabelText(/Approved models/), "claude-sonnet-5");
    await user.click(screen.getByRole("button", { name: "Save vendor" }));

    await waitFor(() => expect(post).toHaveBeenCalled());
    expect(post).toHaveBeenCalledWith("/api/vendors", {
      name: "Anthropic",
      providers: ["anthropic", "bedrock_anthropic"],
      approved_models: ["claude-sonnet-5"],
    });
  });

  it("hides management actions without permissions", async () => {
    render(<VendorsView canManage={false} canRetire={false} />);
    await waitFor(() => expect(screen.getAllByTestId("vendor-card")).toHaveLength(2));
    expect(screen.queryByRole("form", { name: "Register a vendor" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Re-review" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
  });
});

describe("daysUntil", () => {
  it("counts whole days from today in UTC", () => {
    const today = new Date(Date.UTC(2026, 9, 30, 15, 0, 0));
    expect(daysUntil("2026-10-30", today)).toBe(0);
    expect(daysUntil("2026-11-09", today)).toBe(10);
    expect(daysUntil("2026-10-29", today)).toBe(-1);
  });
});

describe("vendor evidence", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(api, "getJson").mockResolvedValue(PAYLOAD as any);
  });

  it("lists each vendor's references and flags an expired one", async () => {
    render(<VendorsView canManage canRetire />);
    await waitFor(() => expect(screen.getAllByTestId("evidence-row")).toHaveLength(2));
    expect(screen.getByText(/BAA 2026/)).toBeInTheDocument();
    expect(screen.getByText(/Evidence has expired/)).toBeInTheDocument();
    expect(screen.getByText(/lapsed; the vendor cannot be approved/i)).toBeInTheDocument();
  });

  it("records a reference against the vendor without a document body", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "postJson").mockResolvedValue({} as any);
    render(<VendorsView canManage canRetire />);
    await waitFor(() => expect(screen.getAllByTestId("vendor-card")).toHaveLength(2));
    await user.click(screen.getAllByText("Record an evidence reference")[0]);
    // both vendors carry a form; scope every query to OpenAI's
    const form = within(screen.getByRole("form", { name: "Record evidence for OpenAI" }));
    await user.selectOptions(form.getByLabelText("Kind"), "soc2_type2");
    await user.type(form.getByLabelText("Name"), "SOC 2 2026");
    await user.type(form.getByLabelText(/Reference number/), "SOC-9");
    await user.type(form.getByLabelText("Issued"), "2026-01-01");
    await user.type(form.getByLabelText("Expires"), "2027-01-01");
    await user.click(form.getByRole("button", { name: "Record reference" }));
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post.mock.calls[0][0]).toBe("/api/vendors/v1/evidence");
    expect(post.mock.calls[0][1]).toEqual({
      kind: "soc2_type2",
      name: "SOC 2 2026",
      identifier: "SOC-9",
      issued_at: "2026-01-01",
      expires_at: "2027-01-01",
      document_hash: null,
    });
  });

  it("hides the record form and withdraw buttons without permissions", async () => {
    render(<VendorsView canManage={false} canRetire={false} />);
    await waitFor(() => expect(screen.getAllByTestId("evidence-row")).toHaveLength(2));
    expect(screen.queryByText("Record an evidence reference")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Withdraw" })).not.toBeInTheDocument();
  });
});
