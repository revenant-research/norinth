"""Fallback page served when the dashboard bundle has not been built.

The compiled React bundle (``app/dashboard/static``) is a build artifact: it is
produced by ``npm run build`` in CI and in the Docker image and is not
committed. If the platform starts without it, say so plainly instead of serving
a stale or alternative UI.
"""

from __future__ import annotations

from html import escape


def dashboard_html(static_dir: str | None = None) -> str:
    location = escape(static_dir or "apps/platform/app/dashboard/static")
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Norinth · dashboard not built</title>
    <style>
      body {{ margin: 0; font-family: -apple-system, "Inter", system-ui, sans-serif; background: #fbfbfa; color: #171717; }}
      main {{ max-width: 640px; margin: 12vh auto; padding: 0 24px; }}
      h1 {{ font-size: 22px; margin: 0 0 8px; }}
      p {{ color: #6b6b66; line-height: 1.5; }}
      pre {{ background: #f4f4f2; border: 1px solid #e5e3dc; border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 13px; }}
      code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    </style>
  </head>
  <body>
    <main>
      <h1>Norinth API is running; the dashboard has not been built.</h1>
      <p>The API (<code>/api/...</code>, <code>/v1/events/batch</code>, <code>/health</code>) is available.
         The web dashboard is a build artifact and was not found at <code>{location}</code>.</p>
      <p>Build it once, then reload:</p>
      <pre><code>make build-frontend</code></pre>
      <p>Docker images build the dashboard automatically. See <code>CONTRIBUTING.md</code>.</p>
    </main>
  </body>
</html>
"""
