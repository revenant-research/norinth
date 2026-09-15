# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

"""A released image and its support files must resolve as one unit."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.build_release_manifest import build_manifest

ROOT = Path(__file__).resolve().parents[1]


def _resolve(
    manifest_path: Path, version: str = "v0.2.2", overrides: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in ("NORINTH_IMAGE", "NORINTH_REPO_RAW", "NORINTH_VERSION"):
        env.pop(name, None)
    env["NORINTH_RELEASE_MANIFEST_URL"] = manifest_path.as_uri()
    env.update(overrides or {})
    return subprocess.run(
        ["bash", str(ROOT / "scripts/install.sh"), "--resolve-only", "--version", version],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_manifest_binds_the_file_bytes_and_resolves_a_digest(tmp_path: Path) -> None:
    for name, content in (
        ("docker-compose.yml", b"services: {}\n"),
        ("scripts/backup.sh", b"backup\n"),
        ("scripts/restore.sh", b"restore\n"),
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    manifest = build_manifest("v0.2.2", "a" * 40, "sha256:" + "b" * 64, tmp_path)
    assert manifest["image"].endswith("@sha256:" + "b" * 64)
    assert set(manifest["files"]) == {
        "docker-compose.yml", "scripts/backup.sh", "scripts/restore.sh"
    }
    path = tmp_path / "release-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    resolved = _resolve(path)
    assert resolved.returncode == 0, resolved.stderr
    assert "v0.2.2 (stable)" in resolved.stdout
    assert "sha256:" + "b" * 64 in resolved.stdout

    manifest["image"] = "ghcr.io/revenant-research/norinth:latest"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    rejected = _resolve(path)
    assert rejected.returncode != 0
    assert "Image does not match the digest" in rejected.stderr


def test_release_resolution_rejects_a_single_override_or_wrong_tag(tmp_path: Path) -> None:
    manifest = {
        "schema": 1,
        "version": "v0.2.2",
        "channel": "stable",
        "source_sha": "a" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "image": "ghcr.io/revenant-research/norinth@sha256:" + "b" * 64,
        "files": {name: "c" * 64 for name in (
            "docker-compose.yml", "scripts/backup.sh", "scripts/restore.sh"
        )},
    }
    path = tmp_path / "release-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    one_override = _resolve(path, overrides={"NORINTH_IMAGE": "norinth:edge"})
    assert one_override.returncode != 0
    assert "Set NORINTH_IMAGE and NORINTH_REPO_RAW together" in one_override.stderr
    wrong_tag = _resolve(path, version="v0.2.3")
    assert wrong_tag.returncode != 0
    assert "does not match the requested tag" in wrong_tag.stderr


@pytest.mark.parametrize("version,sha,digest", [
    ("latest", "a" * 40, "sha256:" + "b" * 64),
    ("v0.2.2", "short", "sha256:" + "b" * 64),
    ("v0.2.2", "a" * 40, "latest"),
])
def test_manifest_builder_rejects_floating_or_invalid_identity(
    tmp_path: Path, version: str, sha: str, digest: str
) -> None:
    with pytest.raises(ValueError):
        build_manifest(version, sha, digest, tmp_path)
