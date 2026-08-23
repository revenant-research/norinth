import { act, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { useResource } from "./useResource";

// `reload` must invoke the latest loader so changing filters re-queries
function Harness() {
  const [filter, setFilter] = useState("a");
  const { value, reload } = useResource(async () => `result:${filter}`);
  return (
    <div>
      <output data-testid="value">{value ?? "loading"}</output>
      <button onClick={() => setFilter("b")}>change filter</button>
      <button onClick={() => reload()}>reload</button>
    </div>
  );
}

describe("useResource", () => {
  it("loads on mount", async () => {
    render(<Harness />);
    await waitFor(() => expect(screen.getByTestId("value")).toHaveTextContent("result:a"));
  });

  it("reload uses the latest loader (filters take effect)", async () => {
    render(<Harness />);
    await waitFor(() => expect(screen.getByTestId("value")).toHaveTextContent("result:a"));
    await act(async () => {
      screen.getByText("change filter").click();
    });
    await act(async () => {
      screen.getByText("reload").click();
    });
    // reload must pick up the new loader and yield result:b
    await waitFor(() => expect(screen.getByTestId("value")).toHaveTextContent("result:b"));
  });
});
