from __future__ import annotations

import os

from app.services.auth import hash_password
from app.storage.workflow import count_super_admins, create_platform_user

DEFAULT_SUPER_ADMIN_EMAIL = "admin@norinth.local"
DEFAULT_SUPER_ADMIN_PASSWORD = "norinth-admin"


def seed_super_admin() -> None:
    """Ensure a platform super admin exists on boot.

    The super admin is the root of the provisioning chain (super admin ->
    organizations -> org admins -> users). Credentials come from the environment
    and fall back to documented development defaults that force a password
    change on first login.
    """
    if count_super_admins() > 0:
        return
    email = os.getenv("NORINTH_SUPER_ADMIN_EMAIL", DEFAULT_SUPER_ADMIN_EMAIL)
    password = os.getenv("NORINTH_SUPER_ADMIN_PASSWORD", DEFAULT_SUPER_ADMIN_PASSWORD)
    using_defaults = (
        os.getenv("NORINTH_SUPER_ADMIN_EMAIL") is None
        or os.getenv("NORINTH_SUPER_ADMIN_PASSWORD") is None
    )
    create_platform_user(
        user_ref=email,
        display_name="Platform Super Admin",
        email=email,
        password_hash=hash_password(password),
        status="active",
        platform_role="super_admin",
        tenant_id=None,
        must_change_password=using_defaults,
    )
