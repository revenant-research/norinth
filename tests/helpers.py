"""shared test helpers"""

from __future__ import annotations


def login_and_activate(test_client, email: str, password: str, new_password: str | None = None):
    """log a user in and complete first-login password rotation if required"""
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
