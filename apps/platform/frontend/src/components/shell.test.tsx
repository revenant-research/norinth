import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Sidebar, SkipLink, useRouteAnnouncement } from "./shell";

const routes = [
  { id: "overview", label: "Overview" },
  { id: "risk", label: "Risk" },
];

function Page({ title }: { title: string }) {
  const ref = useRouteAnnouncement(title);
  return (
    <h1 ref={ref} tabIndex={-1}>
      {title}
    </h1>
  );
}

describe("Sidebar", () => {
  it("is a labelled navigation landmark that marks the current page", () => {
    render(<Sidebar tagline="Workspace" routes={routes} active="risk" />);
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(nav).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Risk" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });
});

describe("SkipLink", () => {
  it("targets the main content landmark", () => {
    render(
      <>
        <SkipLink />
        <main id="main-content">content</main>
      </>,
    );
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute("href", "#main-content");
  });
});

describe("useRouteAnnouncement", () => {
  it("sets the document title and moves focus to the heading on route change", () => {
    const { rerender } = render(<Page title="Overview" />);
    expect(document.title).toBe("Overview · Norinth");
    // initial render must not steal focus from wherever the user was
    expect(document.activeElement).not.toBe(screen.getByRole("heading"));

    rerender(<Page title="Risk" />);
    expect(document.title).toBe("Risk · Norinth");
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Risk" }));
  });
});
