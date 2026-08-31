// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { VendorsView, splitList } from "./vendors";

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
