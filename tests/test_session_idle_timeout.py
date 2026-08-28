"""sessions end after inactivity, not only at the absolute ttl

the absolute 12h lifetime alone leaves a session usable all day on an
abandoned workstation — flagged in the F500 buyer evaluation. activity
extends a session; silence ends it.
"""

from __future__ import annotations

import pathlib
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "apps" / "platform"))

from tests.helpers import login_and_activate  # noqa: E402


def _org_client(super_admin_client, tenant: str):
    from app.main import app
    from fastapi.testclient import TestClient

    super_admin_client.post(
        "/api/admin/organizations",
        json={
            "tenant_id": tenant,
            "name": tenant,
            "admin_email": f"a@{tenant}.test",
            "admin_display_name": "A",
            "admin_password": f"{tenant}-admin-pw-1",
        },
    )
    org = TestClient(app)
    login_and_activate(org, f"a@{tenant}.test", f"{tenant}-admin-pw-1")
    return org


def _backdate_sessions(user_ref: str, minutes: int, column: str = "last_seen_at") -> None:
    from app.storage.raw_events import connect

    past = (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()
    with connect() as connection:
        connection.execute(f"UPDATE sessions SET {column} = ? WHERE user_ref = ?", (past, user_ref))  # noqa: S608


def test_idle_session_is_rejected_and_deleted(super_admin_client):
    from app.services import auth as auth_service
    from app.storage.raw_events import connect

    org = _org_client(super_admin_client, "idle1")
    assert org.get("/api/auth/me").status_code == 200

    _backdate_sessions("a@idle1.test", auth_service.SESSION_IDLE_MINUTES + 5)
    assert org.get("/api/auth/me").status_code == 401

    # the row is gone, not just refused
    with connect() as connection:
        rows = connection.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_ref = ?", ("a@idle1.test",)).fetchone()
    assert rows["n"] == 0
    org.close()


def test_activity_within_the_window_extends_the_session(super_admin_client):
    from app.services import auth as auth_service
    from app.storage.raw_events import connect

    org = _org_client(super_admin_client, "idle2")
    backdated_by = auth_service.SESSION_IDLE_MINUTES - 5
    _backdate_sessions("a@idle2.test", backdated_by)

    assert org.get("/api/auth/me").status_code == 200

    # the request refreshed last_seen_at, so the clock restarted
    with connect() as connection:
        row = connection.execute("SELECT last_seen_at FROM sessions WHERE user_ref = ?", ("a@idle2.test",)).fetchone()
    refreshed = datetime.fromisoformat(row["last_seen_at"])
    assert datetime.now(UTC) - refreshed < timedelta(minutes=1)
    org.close()


def test_legacy_session_without_activity_column_falls_back_to_created_at(super_admin_client):
    """rows from before the migration must age out, not be grandfathered in"""
    from app.services import auth as auth_service
    from app.storage.raw_events import connect

    org = _org_client(super_admin_client, "idle3")
    with connect() as connection:
        connection.execute("UPDATE sessions SET last_seen_at = NULL WHERE user_ref = ?", ("a@idle3.test",))
    _backdate_sessions("a@idle3.test", auth_service.SESSION_IDLE_MINUTES + 5, column="created_at")

    assert org.get("/api/auth/me").status_code == 401
    org.close()


def test_idle_timeout_can_be_disabled(super_admin_client, monkeypatch):
    from app.services import auth as auth_service

    org = _org_client(super_admin_client, "idle4")
    monkeypatch.setattr(auth_service, "SESSION_IDLE_MINUTES", 0)
    _backdate_sessions("a@idle4.test", 600)

    assert org.get("/api/auth/me").status_code == 200
    org.close()


def test_absolute_expiry_still_applies_even_with_recent_activity(super_admin_client):
    from app.storage.raw_events import connect

    org = _org_client(super_admin_client, "idle5")
    past = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    with connect() as connection:
        connection.execute("UPDATE sessions SET expires_at = ? WHERE user_ref = ?", (past, "a@idle5.test"))

    assert org.get("/api/auth/me").status_code == 401
    org.close()
