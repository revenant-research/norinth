import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import { ComplianceView, FrameworkCoverageCards, coverageTone } from "./compliance";

const coverage = [
  { framework: "NIST AI RMF", total_requirements: 10, satisfied: 9, coverage_pct: 90, gaps: ["NIST AI RMF MEASURE 2.7"], satisfied_requirements: [] },
  { framework: "EU AI Act", total_requirements: 4, satisfied: 1, coverage_pct: 25, gaps: ["EU AI Act Art 12", "EU AI Act Art 14", "EU AI Act Art 26"], satisfied_requirements: [] },
  { framework: "SOC 2", total_requirements: 2, satisfied: 2, coverage_pct: 100, gaps: [], satisfied_requirements: ["SOC 2 CC7.2", "SOC 2 CC6.1"] },
];

describe("coverageTone", () => {
  it("buckets by percentage", () => {
    expect(coverageTone(90)).toBe("good");
    expect(coverageTone(60)).toBe("mid");
    expect(coverageTone(20)).toBe("low");
  });
});

describe("FrameworkCoverageCards", () => {
  it("renders a card per framework with an accessible progress bar and expandable gaps", async () => {
    const user = userEvent.setup();
    render(<FrameworkCoverageCards rows={coverage as any} />);
    expect(screen.getAllByTestId("framework-card")).toHaveLength(3);
    expect(screen.getByRole("progressbar", { name: "25% coverage" })).toHaveAttribute("aria-valuenow", "25");
    expect(screen.getByText("All mapped requirements have evidence.")).toBeInTheDocument();

    const toggle = screen.getByRole("button", { name: "Show 3 outstanding requirements" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(screen.getByRole("list", { name: "Outstanding requirements for EU AI Act" })).toBeInTheDocument();
    expect(screen.getByText("EU AI Act Art 14")).toBeInTheDocument();
  });
});

describe("ComplianceView", () => {
  beforeEach(() => {
    vi.spyOn(api, "getJson").mockImplementation(async (path: string) => {
      if (path === "/api/compliance/framework-coverage") return { framework_coverage: coverage } as any;
      if (path === "/api/compliance/audit-packet") {
        return {
          generated_at: "2026-08-23T12:00:00+00:00",
          risk_findings: [{}, {}],
          control_assessments: [{}, {}, {}],
          audit_trail: { integrity: { ok: true } },
        } as any;
      }
      throw new Error(path);
    });
  });

  it("summarizes coverage and exports the packet with an integrity verdict", async () => {
    const user = userEvent.setup();
    // jsdom has no object urls; stub the download primitives and capture the anchor click
    const objectUrl = vi.fn(() => "blob:norinth");
    Object.defineProperty(URL, "createObjectURL", { value: objectUrl, configurable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: vi.fn(), configurable: true });
    const clicked: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this.download);
    });
    render(<ComplianceView scope={{}} tenantId="acme" />);
    await waitFor(() => expect(screen.getAllByTestId("framework-card")).toHaveLength(3));
    // average of 90, 25, 100 => 72%; gaps 1 + 3 + 0 = 4
    expect(screen.getByText("72%")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();

    await user.click(screen.getByTestId("export-packet"));
    await waitFor(() => expect(screen.getByTestId("packet-summary")).toBeInTheDocument());
    expect(objectUrl).toHaveBeenCalled();
    expect(clicked[0]).toMatch(/^norinth-audit-packet-acme-/);
    expect(screen.getAllByText("verified").length).toBeGreaterThanOrEqual(2); // metric card + packet summary
  });
});
