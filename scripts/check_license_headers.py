#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research
"""Verify (or insert) SPDX license headers on source files.

Every distributable source file must carry an SPDX short-form header so the
Apache-2.0 copyright notice travels with the file (License Section 4(c)):

    # SPDX-License-Identifier: Apache-2.0
    # Copyright 2026 Revenant Research

Usage:
  python scripts/check_license_headers.py            # check, exit 1 if any missing
  python scripts/check_license_headers.py --fix      # insert missing headers
  python scripts/check_license_headers.py <files...>  # check only these (pre-commit)
"""

from __future__ import annotations

import sys
from pathlib import Path

OWNER = "Revenant Research"
YEAR = "2026"
SPDX = "SPDX-License-Identifier: Apache-2.0"

COMMENT = {".py": "#", ".ts": "//", ".tsx": "//"}
ROOTS = ("apps", "packages", "scripts")
SKIP_DIRS = {"node_modules", "dist", "build", ".venv", "__pycache__"}


def header_for(ext: str) -> str:
    c = COMMENT[ext]
    return f"{c} {SPDX}\n{c} Copyright {YEAR} {OWNER}\n"


def iter_default_files(repo: Path):
    for root in ROOTS:
        base = repo / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.suffix not in COMMENT:
                continue
            if SKIP_DIRS & set(path.parts):
                continue
            yield path


def has_header(text: str) -> bool:
    # Look only at the top of the file (past an optional shebang).
    head = "\n".join(text.splitlines()[:5])
    return SPDX in head


def insert_header(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    prefix = ""
    if lines and lines[0].startswith("#!"):
        prefix = lines[0]
        lines = lines[1:]
    body = "".join(lines)
    path.write_text(prefix + header_for(path.suffix) + "\n" + body, encoding="utf-8")


def main(argv: list[str]) -> int:
    repo = Path(__file__).resolve().parent.parent
    fix = "--fix" in argv
    file_args = [a for a in argv if not a.startswith("-")]

    if file_args:
        candidates = [Path(a) for a in file_args if Path(a).suffix in COMMENT]
    else:
        candidates = list(iter_default_files(repo))

    missing: list[Path] = []
    for path in candidates:
        if not path.exists() or SKIP_DIRS & set(path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        if text.strip() == "":  # empty __init__.py etc. — nothing to protect
            continue
        if has_header(text):
            continue
        if fix:
            insert_header(path)
            print(f"added header: {path}")
        else:
            missing.append(path)

    if missing:
        rel = [str(p.relative_to(repo)) if p.is_absolute() else str(p) for p in missing]
        print("Missing SPDX license header:", file=sys.stderr)
        for r in rel:
            print(f"  {r}", file=sys.stderr)
        print(
            "\nRun: python scripts/check_license_headers.py --fix",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
