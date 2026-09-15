# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""Build the release manifest from the files and image digest actually shipped."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SUPPORT_FILES = ("docker-compose.yml", "scripts/backup.sh", "scripts/restore.sh")


def build_manifest(version: str, source_sha: str, image_digest: str, root: Path) -> dict:
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("version must be a version tag such as v0.2.2")
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source SHA must be a full lowercase Git commit SHA")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise ValueError("image digest must be an immutable sha256 digest")
    files = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in SUPPORT_FILES
    }
    return {
        "schema": 1,
        "version": version,
        "channel": "stable",
        "source_sha": source_sha,
        "image": f"ghcr.io/revenant-research/norinth@{image_digest}",
        "image_digest": image_digest,
        "files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_manifest(args.version, args.source_sha, args.image_digest, args.root)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
