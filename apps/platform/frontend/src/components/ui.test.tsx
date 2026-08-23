import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { RecordList } from "./ui";

function cards(count: number) {
  return Array.from({ length: count }, (_, i) => (
    <article key={i} data-testid="card">
      Record {i}
    </article>
  ));
}

describe("RecordList", () => {
  it("renders the empty state when there is nothing to show", () => {
    render(<RecordList empty="Nothing here">{[]}</RecordList>);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("mounts only the first window and expands on demand", async () => {
    render(<RecordList empty="" pageSize={10}>{cards(37)}</RecordList>);
    expect(screen.getAllByTestId("card")).toHaveLength(10);
    expect(screen.getByRole("status")).toHaveTextContent("Showing 10 of 37 records");

    await userEvent.click(screen.getByRole("button", { name: "Show 10 more" }));
    expect(screen.getAllByTestId("card")).toHaveLength(20);

    await userEvent.click(screen.getByRole("button", { name: "Show all 37" }));
    expect(screen.getAllByTestId("card")).toHaveLength(37);
    // Everything is visible: the footer disappears.
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("reports the server total when only one page is loaded", () => {
    render(
      <RecordList empty="" pageSize={50} total={1200} label="events">
        {cards(200)}
      </RecordList>,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Showing 50 of 1200 events (200 loaded)");
  });

  it("renders every card without a footer when the list fits the window", () => {
    render(<RecordList empty="" pageSize={25}>{cards(5)}</RecordList>);
    expect(screen.getAllByTestId("card")).toHaveLength(5);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
