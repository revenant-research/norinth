"""the pinned lock stays in step with the declared requirements

requirements.txt states intent with lower bounds; the image installs the lock with
--require-hashes. if the two drift, the audited dependency set is not the shipped
one, which is the whole reason for locking
"""

from __future__ import annotations

import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIREMENTS = REPO_ROOT / "apps" / "platform" / "requirements.txt"
LOCK = REPO_ROOT / "apps" / "platform" / "requirements.lock.txt"


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _declared_names() -> set[str]:
    names = set()
    for line in REQUIREMENTS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        names.add(_normalize(re.split(r"[<>=!\[;]", line)[0].strip()))
    return names


def _locked_versions() -> dict[str, str]:
    versions = {}
    for line in LOCK.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?==([^\s\\]+)", line)
        if match:
            versions[_normalize(match.group(1))] = match.group(2)
    return versions


def test_every_declared_requirement_is_pinned_in_the_lock():
    missing = _declared_names() - set(_locked_versions())
    assert not missing, f"declared but not locked (run `make lock`): {sorted(missing)}"


def test_lock_pins_exact_versions_with_hashes():
    locked = _locked_versions()
    assert len(locked) >= len(_declared_names()), "lock must include transitive dependencies"
    for name, version in locked.items():
        assert re.match(r"^\d", version), f"{name} is not pinned to a concrete version: {version}"
    assert "--hash=sha256:" in LOCK.read_text(), "lock must carry artifact hashes"


def test_the_image_installs_the_lock_not_the_loose_requirements():
    dockerfile = (REPO_ROOT / "apps" / "platform" / "Dockerfile").read_text()
    assert "--require-hashes -r requirements.lock.txt" in dockerfile
    assert "pip install --no-cache-dir -r requirements.txt" not in dockerfile


def test_base_images_are_digest_pinned():
    """a tag can be repointed after review; a digest cannot"""
    dockerfile = (REPO_ROOT / "apps" / "platform" / "Dockerfile").read_text()
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert from_lines
    for line in from_lines:
        assert "@sha256:" in line, f"base image is not digest-pinned: {line}"

    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    for line in compose.splitlines():
        stripped = line.strip()
        # the norinth image itself is overridable by tag for local builds
        if stripped.startswith("image: postgres"):
            assert "@sha256:" in stripped, f"third-party image is not digest-pinned: {stripped}"
