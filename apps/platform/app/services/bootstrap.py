from __future__ import annotations

import os

from app.services.auth import hash_password
from app.storage.ingestion_keys import seed_dev_ingestion_key
from app.storage.workflow import count_super_admins, create_platform_user

DEFAULT_SUPER_ADMIN_EMAIL = "admin@norinth.local"
DEFAULT_SUPER_ADMIN_PASSWORD = "norinth-admin"
DEFAULT_DEV_INGEST_TENANT = "tenant-local"


def using_development_defaults() -> bool:
    """true when running on documented dev defaults

    production sets NORINTH_SUPER_ADMIN_PASSWORD; unset means local dev where we
    may seed dev conveniences like the well-known ``dev`` ingestion key
    """
    return os.getenv("NORINTH_SUPER_ADMIN_PASSWORD") is None


def seed_dev_ingestion_key_if_dev() -> None:
    """seed the well-known ``dev`` ingestion key in development only

    bound to a single tenant so even the dev token can't forge telemetry for
    another tenant. production never gets this key
    """
    if not using_development_defaults():
        return
    tenant = os.getenv("NORINTH_DEV_INGEST_TENANT", DEFAULT_DEV_INGEST_TENANT)
    seed_dev_ingestion_key(tenant_id=tenant)


def seed_super_admin() -> None:
    """create a platform super admin on boot if none exists

    root of the provisioning chain (super admin -> orgs -> org admins -> users).
    credentials come from the env, falling back to dev defaults that force a
    password change on first login
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
