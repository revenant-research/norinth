from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.admin import router as admin_router
from app.api.agents import router as agents_router
from app.api.auth import router as auth_router
from app.api.compliance import router as compliance_router
from app.api.ingestion_keys import router as ingestion_keys_router
from app.api.intake import router as intake_router
from app.api.routes import router as api_router
from app.api.scim import router as scim_router
from app.api.sso import router as sso_router
from app.dashboard.html import dashboard_html
from app.dependencies import SESSION_COOKIE
from app.ingestion.routes import router as ingestion_router
from app.services.auth import resolve_session
from app.services.bootstrap import seed_dev_ingestion_key_if_dev, seed_super_admin
from app.storage.agents import init_agents
from app.storage.audit import init_audit
from app.storage.deployments import init_deployments
from app.storage.entities import init_entities
from app.storage.governance_policy import init_governance_policy
from app.storage.incidents import init_incidents
from app.storage.ingestion_keys import init_ingestion_keys
from app.storage.intake import init_intake
from app.storage.lifecycle import init_lifecycle
from app.storage.login_attempts import init_login_attempts
from app.storage.organizations import init_organizations
from app.storage.prompts import init_prompts
from app.storage.raw_events import init_storage
from app.storage.scim import init_scim
from app.storage.sso import init_sso
from app.storage.workflow import init_workflow, load_platform_user

STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"
ASSETS_DIR = STATIC_DIR / "assets"
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(title="Norinth Platform Sandbox")

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
init_login_attempts()
init_sso()
init_scim()
init_agents()
seed_super_admin()
seed_dev_ingestion_key_if_dev()
app.include_router(ingestion_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(intake_router)
app.include_router(api_router)
app.include_router(compliance_router)
app.include_router(ingestion_keys_router)
app.include_router(sso_router)
app.include_router(scim_router)
app.include_router(agents_router)

# Endpoints reachable while a user still owes a password change.
_PASSWORD_CHANGE_ALLOWLIST = {
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/change-password",
    "/api/auth/sso/callback",
}


_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """Defense-in-depth CSRF protection for cookie-authenticated mutations.

    Browsers send an ``Origin`` header on state-changing requests and forbid
    scripts from forging it, so requiring Origin to match the request host on
    mutating /api/* calls blocks cross-site request forgery. Requests without an
    Origin (non-browser API clients, which don't carry a victim's ambient
    cookies) are unaffected. Ingestion (/v1/*) uses key auth, not cookies, so it
    is out of scope. This complements the cookie's SameSite=lax (audit H-8).
    """
    if request.method in _MUTATING_METHODS and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin:
            expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
            # Compare only scheme+host+port; browsers send Origin without a path.
            if origin.rstrip("/") != expected.rstrip("/"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-origin request rejected"},
                )
    return await call_next(request)


@app.middleware("http")
async def enforce_password_change(request: Request, call_next):
    """Server-side gate: a user flagged must_change_password may reach only the
    auth allowlist until they rotate their credential.

    Previously this was enforced only in the frontend, so anyone holding a
    temporary password could drive the entire API with curl indefinitely
    (audit C-4). Ingestion (`/v1/...`) uses key auth and is unaffected.
    """
    path = request.url.path
    if path.startswith("/api/") and path not in _PASSWORD_CHANGE_ALLOWLIST:
        user_ref = resolve_session(request.cookies.get(SESSION_COOKIE))
        if user_ref:
            user = load_platform_user(user_ref)
            if user and user.get("must_change_password"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Password change required before continuing"},
                )
    return await call_next(request)


if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="platform-assets")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    if INDEX_FILE.exists():
        return HTMLResponse(
            INDEX_FILE.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    return dashboard_html()
