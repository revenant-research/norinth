"""Shared pytest fixtures for the Norinth platform.

Every test runs against its own throwaway SQLite database so tests are
isolated and idempotent (unlike scripts/verify_live.py, which requires a
fresh DB per run). The storage layer resolves ``NORINTH_PLATFORM_DB`` at
call time, so pointing the env var at a fresh file and re-running the
idempotent ``init_*`` functions gives each test a clean database.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PLATFORM_DIR = REPO_ROOT / "apps" / "platform"
sys.path.insert(0, str(PLATFORM_DIR))

# Point at a throwaway DB before importing the app, so its import-time
# initialization never touches a real database.
_bootstrap_db = pathlib.Path(tempfile.mkdtemp(prefix="norinth-boot-")) / "boot.sqlite3"
os.environ["NORINTH_PLATFORM_DB"] = str(_bootstrap_db)

DEFAULT_ADMIN_EMAIL = "admin@norinth.local"
DEFAULT_ADMIN_PASSWORD = "norinth-admin"


def _reinitialize_database() -> None:
    from app.services.bootstrap import seed_dev_ingestion_key_if_dev, seed_super_admin
    from app.storage.audit import init_audit
    from app.storage.deployments import init_deployments
    from app.storage.entities import init_entities
    from app.storage.governance_policy import init_governance_policy
    from app.storage.incidents import init_incidents
    from app.storage.ingestion_keys import init_ingestion_keys
    from app.storage.intake import init_intake
    from app.storage.lifecycle import init_lifecycle
    from app.storage.organizations import init_organizations
    from app.storage.prompts import init_prompts
    from app.storage.raw_events import init_storage
    from app.storage.workflow import init_workflow

    init_storage()
    init_entities()
    init_governance_policy()
    init_lifecycle()
    init_workflow()
    init_deployments()
    init_incidents()
    init_prompts()
    init_organizations()
    init_intake()
    init_audit()
    init_ingestion_keys()
    seed_super_admin()
    seed_dev_ingestion_key_if_dev()


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Point the platform at a fresh, fully-initialized database."""
    db_path = tmp_path / "test.sqlite3"
    monkeypatch.setenv("NORINTH_PLATFORM_DB", str(db_path))
    _reinitialize_database()
    return db_path


@pytest.fixture
def client(fresh_db):
    """A FastAPI TestClient bound to a fresh per-test database."""
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def super_admin_client(client):
    """A client already logged in as the bootstrap super admin."""
    resp = client.post(
        "/api/auth/login",
        json={"email": DEFAULT_ADMIN_EMAIL, "password": DEFAULT_ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    return client
