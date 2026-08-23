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

os.environ.setdefault("NORINTH_NOTIFICATIONS_WORKER", "0")  # deliver synchronously in tests

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PLATFORM_DIR = REPO_ROOT / "apps" / "platform"
sys.path.insert(0, str(PLATFORM_DIR))

# Backend selection. By default tests run on a throwaway SQLite file. Setting
# NORINTH_TEST_DATABASE_URL=postgresql://... runs the same suite against
# PostgreSQL (the schema is dropped and recreated for every test).
POSTGRES_TEST_URL = os.getenv("NORINTH_TEST_DATABASE_URL")
if POSTGRES_TEST_URL:
    os.environ["NORINTH_DATABASE_URL"] = POSTGRES_TEST_URL
else:
    os.environ.pop("NORINTH_DATABASE_URL", None)
    # Point at a throwaway DB before importing the app, so its import-time
    # initialization never touches a real database.
    _bootstrap_db = pathlib.Path(tempfile.mkdtemp(prefix="norinth-boot-")) / "boot.sqlite3"
    os.environ["NORINTH_PLATFORM_DB"] = str(_bootstrap_db)

DEFAULT_ADMIN_EMAIL = "admin@norinth.local"
DEFAULT_ADMIN_PASSWORD = "norinth-admin"


def _reinitialize_database() -> None:
    from app.services.bootstrap import seed_dev_ingestion_key_if_dev, seed_super_admin
    from app.storage.migrations import run_migrations

    run_migrations()
    seed_super_admin()
    seed_dev_ingestion_key_if_dev()


def _reset_postgres_schema() -> None:
    import psycopg

    with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute("CREATE SCHEMA public")


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """Point the platform at a fresh, fully-initialized database."""
    if POSTGRES_TEST_URL:
        _reset_postgres_schema()
        _reinitialize_database()
        return POSTGRES_TEST_URL
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


ROTATED_ADMIN_PASSWORD = "rotated-admin-pw-123456"


@pytest.fixture
def super_admin_client(client):
    """A super-admin client that has completed first-login password rotation.

    The bootstrap admin is created with must_change_password=True, so the real
    flow is: log in, change the password, then operate. This fixture performs
    that rotation and returns an operational client.
    """
    login = client.post(
        "/api/auth/login",
        json={"email": DEFAULT_ADMIN_EMAIL, "password": DEFAULT_ADMIN_PASSWORD},
    )
    assert login.status_code == 200, login.text
    changed = client.post(
        "/api/auth/change-password",
        json={
            "current_password": DEFAULT_ADMIN_PASSWORD,
            "new_password": ROTATED_ADMIN_PASSWORD,
        },
    )
    assert changed.status_code == 200, changed.text
    return client
