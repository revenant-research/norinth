"""Shared test helpers."""

from __future__ import annotations


def login_and_activate(test_client, email: str, password: str, new_password: str | None = None):
    """Log a user in and complete first-login password rotation if required.

    Newly-provisioned users are created with must_change_password=True, which the
    server now enforces (audit C-4): they can log in but cannot use the rest of
    the API until they rotate their password. This mirrors the real UX flow.
    """
    login = test_client.post("/api/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    if login.json()["user"].get("must_change_password"):
        rotated = new_password or f"{password}-rotated-1"
        changed = test_client.post(
            "/api/auth/change-password",
            json={"current_password": password, "new_password": rotated},
        )
        assert changed.status_code == 200, changed.text
    return test_client
