from __future__ import annotations

import os

from app.services.auth import hash_password
from app.storage.ingestion_keys import seed_dev_ingestion_key
from app.storage.workflow import count_super_admins, create_platform_user

DEFAULT_SUPER_ADMIN_EMAIL = "admin@norinth.local"
DEFAULT_SUPER_ADMIN_PASSWORD = "norinth-admin"
DEFAULT_DEV_INGEST_TENANT = "tenant-local"


def using_development_defaults() -> bool:
    """True when the platform is running on documented dev defaults.

    Production deployments set NORINTH_SUPER_ADMIN_PASSWORD; when it is unset we
    are in local development and may seed developer conveniences (the well-known
    ``dev`` ingestion key), which are never seeded otherwise.
    """
    return os.getenv("NORINTH_SUPER_ADMIN_PASSWORD") is None


def seed_dev_ingestion_key_if_dev() -> None:
    """Seed the well-known ``dev`` ingestion key in development only.

    The key is bound to a single tenant, so even the dev token cannot forge
    telemetry for another tenant (audit C-1). Production (env-configured) never
    gets this key.
    """
    if not using_development_defaults():
        return
    tenant = os.getenv("NORINTH_DEV_INGEST_TENANT", DEFAULT_DEV_INGEST_TENANT)
    seed_dev_ingestion_key(tenant_id=tenant)


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
