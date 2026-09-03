"""shared pytest fixtures and per-test db setup"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile

import pytest

os.environ.setdefault("NORINTH_NOTIFICATIONS_WORKER", "0")  # deliver synchronously in tests
os.environ.setdefault("NORINTH_MAINTENANCE_WORKER", "0")  # run maintenance passes explicitly in tests
os.environ.setdefault("NORINTH_FOLD_SWEEPER", "0")  # fold pending explicitly in tests, no background sweep
os.environ.setdefault("NORINTH_ALLOW_PRIVATE_EGRESS", "1")  # test webhook receivers run on 127.0.0.1
# secret storage fails closed without a key; give the suite a real key so secrets are encrypted at rest
os.environ.setdefault("NORINTH_SECRET_KEY", "bm9yaW50aC10ZXN0LW9ubHktbWFzdGVyLWtleS0zMmI")
# keep password hashing fast in tests; prod uses the 600k default
os.environ.setdefault("NORINTH_PBKDF2_ITERATIONS", "20000")

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PLATFORM_DIR = REPO_ROOT / "apps" / "platform"
sys.path.insert(0, str(PLATFORM_DIR))

# backend selection; default sqlite file, NORINTH_TEST_DATABASE_URL runs against postgres (schema dropped/recreated per test)
POSTGRES_TEST_URL = os.getenv("NORINTH_TEST_DATABASE_URL")
if POSTGRES_TEST_URL:
    os.environ["NORINTH_DATABASE_URL"] = POSTGRES_TEST_URL
else:
    os.environ.pop("NORINTH_DATABASE_URL", None)
    # point at a throwaway db before importing the app so import-time init never touches a real db
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

    # pooled idle connections belong to the schema being dropped; start each
    # test from a cold pool so no cached state crosses the reset
    from app.storage.db import close_pg_pool

    close_pg_pool()
    with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute("CREATE SCHEMA public")


@pytest.fixture(autouse=True)
def _isolated_sdk_spool(tmp_path, monkeypatch):
    """the sdk spools undelivered batches under XDG_STATE_HOME by default; keep
    test batches out of the developer's real state directory"""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """point the platform at a fresh initialized db"""
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
    """fastapi testclient bound to a fresh per-test db"""
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as test_client:
        yield test_client


ROTATED_ADMIN_PASSWORD = "rotated-admin-pw-123456"


@pytest.fixture
def super_admin_client(client):
    """super-admin client that has completed first-login password rotation"""
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
