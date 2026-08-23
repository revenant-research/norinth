#!/usr/bin/env python3
"""Fail CI when product copy or docs contain statements that need a source.

Checks landing-page copy and the docs for: email addresses that are not
operator placeholders, response-time promises, hardware sizing numbers,
marketing superlatives, pricing claims about third parties, and ticket-style
audit references in code comments. Dated regulatory claims are allowed only
if the same date appears in docs/SOURCES.md.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
COPY = [
    ROOT / "apps/platform/frontend/src/components/landing.tsx",
    ROOT / "apps/platform/frontend/src/components/guide.tsx",
    ROOT / "apps/platform/frontend/src/components/docs.tsx",
    ROOT / "apps/platform/frontend/index.html",
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "apps/platform/README.md",
    ROOT / "packages/python-sdk/README.md",
    ROOT / "docs/operations.md",
    ROOT / "docs/threat-model.md",
    ROOT / "docs/GTM_STRATEGY.md",
]
ALLOWED_EMAIL_DOMAINS = (".local", ".test", ".example", "example.com", "example.test")
FORBIDDEN = [
    (r"within (one|a few|\d+) (business )?(day|hour)s?", "response-time promise"),
    (r"\b\d+ ?(GB|vCPU|CPU cores?)\b", "hardware sizing number"),
    (r"\b(six|five|seven)-figure|\$\d", "pricing claim"),
    (r"\b(enterprise[- ]grade|world[- ]class|battle[- ]tested|industry[- ]leading|best[- ]in[- ]class|trusted by)\b", "marketing superlative"),
    (r"\b(table[- ]stakes|buyers? (require|expect))\b", "unsourced market claim"),
    (r"\bCHAI\b|Joint Commission", "affiliation-sensitive name outside SOURCES.md"),
]
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DATE = re.compile(r"\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{4}\b")


def _norm_date(value: str) -> str:
    day, month, year = value.split()
    return f"{int(day)} {month[:3].lower()} {year}"


def main() -> int:
    sources = (ROOT / "docs/SOURCES.md").read_text(encoding="utf-8")
    sourced_dates = {_norm_date(m.group(0)) for m in DATE.finditer(sources)}
    problems: list[str] = []
    for path in COPY:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT)
        for match in EMAIL.finditer(text):
            email = match.group(0)
            if not email.lower().endswith(ALLOWED_EMAIL_DOMAINS) and "@postgres" not in email:
                problems.append(f"{rel}: email address {email!r} (use an operator-configured value)")
        for pattern, label in FORBIDDEN:
            if path.name == "SOURCES.md":
                continue
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                if label.startswith("affiliation") and match.group(0) in sources:
                    continue  # named with a primary source in SOURCES.md
                problems.append(f"{rel}: {label}: {match.group(0)!r}")
        for match in DATE.finditer(text):
            if _norm_date(match.group(0)) not in sourced_dates:
                problems.append(f"{rel}: dated claim {match.group(0)!r} not in docs/SOURCES.md")
    code_dirs = [ROOT / "apps/platform/app", ROOT / "packages/python-sdk/norinth_logger", ROOT / "apps/platform/frontend/src"]
    ticket = re.compile(r"\(audit\b|audit [A-Z]+-?\d+|roadmap #\d+|\bGTM\b")
    for directory in code_dirs:
        for path in directory.rglob("*"):
            if path.suffix not in {".py", ".ts", ".tsx"} or ".test." in path.name:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if ticket.search(line):
                    problems.append(f"{path.relative_to(ROOT)}:{number}: ticket/strategy reference in code: {line.strip()[:80]}")
    if problems:
        print("Unsourced or disallowed statements found:")
        for problem in problems:
            print("  -", problem)
        return 1
    print("claims check: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
