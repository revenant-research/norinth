// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import { useEffect, useRef } from "react";

export type RouteItem = { id: string; label: string; description?: string; group?: string };

// app sidebar: labelled nav landmark with `aria-current` on the active route so
// screen readers announce where the user is
export function Sidebar({ tagline, routes, active }: { tagline: string; routes: RouteItem[]; active: string }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        Norinth
        <span className="brand-sub">Revenant Research</span>
      </div>
      <p>{tagline}</p>
      <nav aria-label="Primary">
        {groupRoutes(routes).map(([group, items]) => (
          <div className="nav-group" key={group || "_top"}>
            {group ? <div className="nav-group-label">{group}</div> : null}
            {items.map((item) => (
              <a
                className={active === item.id ? "active" : ""}
                href={`#${item.id}`}
                key={item.id}
                aria-current={active === item.id ? "page" : undefined}
              >
                {item.label}
              </a>
            ))}
          </div>
        ))}
      </nav>
    </aside>
  );
}

/** preserve first-seen group order; ungrouped items come first */
function groupRoutes(routes: RouteItem[]): Array<[string, RouteItem[]]> {
  const order: string[] = [];
  const by = new Map<string, RouteItem[]>();
  for (const route of routes) {
    const key = route.group ?? "";
    if (!by.has(key)) {
      by.set(key, []);
      order.push(key);
    }
    by.get(key)!.push(route);
  }
  return order.map((key) => [key, by.get(key)!]);
}

/** lets keyboard users jump past the sidebar to page content */
export function SkipLink() {
  return (
    <a className="skip-link" href="#main-content">
      Skip to main content
    </a>
  );
}

// hash routing doesn't reload the document, so the browser never moves focus or
// updates the title on nav. this hook sets `document.title` and moves focus to
// the page heading on route change
export function useRouteAnnouncement(title: string) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const previous = useRef<string | null>(null);
  useEffect(() => {
    document.title = `${title} · Norinth`;
    if (previous.current !== null && previous.current !== title) {
      headingRef.current?.focus();
    }
    previous.current = title;
  }, [title]);
  return headingRef;
}
