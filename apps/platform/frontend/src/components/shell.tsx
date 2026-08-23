import { useEffect, useRef } from "react";

export type RouteItem = { id: string; label: string; description?: string };

/**
 * Application sidebar: a labelled navigation landmark with `aria-current` on
 * the active route so screen readers announce where the user is.
 */
export function Sidebar({ tagline, routes, active }: { tagline: string; routes: RouteItem[]; active: string }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        Norinth
        <span className="brand-sub">Revenant Research</span>
      </div>
      <p>{tagline}</p>
      <nav aria-label="Primary">
        {routes.map((item) => (
          <a
            className={active === item.id ? "active" : ""}
            href={`#${item.id}`}
            key={item.id}
            aria-current={active === item.id ? "page" : undefined}
          >
            {item.label}
          </a>
        ))}
      </nav>
    </aside>
  );
}

/** Keyboard users can jump past the sidebar straight to the page content. */
export function SkipLink() {
  return (
    <a className="skip-link" href="#main-content">
      Skip to main content
    </a>
  );
}

/**
 * Hash routing does not reload the document, so browsers never move focus or
 * update the title on navigation. This hook announces route changes by
 * updating `document.title` and moving focus to the page heading.
 */
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
