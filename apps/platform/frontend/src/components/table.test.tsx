// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { DataTable } from "./table";

type Row = { id: string; name: string; count: number };

const rows: Row[] = [
  { id: "b", name: "beta", count: 5 },
  { id: "a", name: "alpha", count: 12 },
  { id: "c", name: "carol", count: 1 },
];

function names(): string[] {
  return screen.getAllByRole("row").slice(1).map((row) => within(row).getAllByRole("cell")[0].textContent || "");
}

function subject(initialSort?: { key: string; direction: "asc" | "desc" }) {
  return (
    <DataTable<Row>
      label="rows"
      empty="Nothing here."
      rows={rows}
      rowKey={(row) => row.id}
      initialSort={initialSort}
      columns={[
        { key: "name", label: "Name" },
        { key: "count", label: "Count", align: "right" },
      ]}
    />
  );
}

describe("DataTable", () => {
  it("sorts by a column, toggles direction, and reports aria-sort", async () => {
    const user = userEvent.setup();
    render(subject());
    expect(names()).toEqual(["beta", "alpha", "carol"]); // insertion order before sorting

    await user.click(screen.getByRole("button", { name: /name/i }));
    expect(names()).toEqual(["alpha", "beta", "carol"]);
    expect(screen.getByRole("columnheader", { name: /name/i })).toHaveAttribute("aria-sort", "ascending");

    await user.click(screen.getByRole("button", { name: /name/i }));
    expect(names()).toEqual(["carol", "beta", "alpha"]);
    expect(screen.getByRole("columnheader", { name: /name/i })).toHaveAttribute("aria-sort", "descending");
  });

  it("sorts numbers numerically", async () => {
    const user = userEvent.setup();
    render(subject());
    await user.click(screen.getByRole("button", { name: /count/i }));
    expect(names()).toEqual(["carol", "beta", "alpha"]); // 1, 5, 12
  });

  it("applies an initial sort", () => {
    render(subject({ key: "count", direction: "desc" }));
    expect(names()).toEqual(["alpha", "beta", "carol"]); // 12, 5, 1
  });

  it("filters rows with the search box and reports the count", async () => {
    const user = userEvent.setup();
    render(subject());
    await user.type(screen.getByRole("searchbox", { name: /search rows/i }), "al");
    expect(names()).toEqual(["alpha"]);
    expect(screen.getByText("1 of 3 rows")).toBeInTheDocument();

    await user.clear(screen.getByRole("searchbox", { name: /search rows/i }));
    await user.type(screen.getByRole("searchbox", { name: /search rows/i }), "zzz");
    expect(screen.queryAllByRole("row")).toHaveLength(0);
    expect(screen.getByText('No rows match "zzz".')).toBeInTheDocument();
  });

  it("shows the empty message when there are no rows", () => {
    render(
      <DataTable<Row>
        label="rows"
        empty="Nothing here."
        rows={[]}
        rowKey={(row) => row.id}
        columns={[{ key: "name", label: "Name" }]}
      />,
    );
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });
});
