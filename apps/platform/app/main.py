from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.compliance import router as compliance_router
from app.api.intake import router as intake_router
from app.dashboard.html import dashboard_html
from app.ingestion.routes import router as ingestion_router
from app.services.bootstrap import seed_super_admin
from app.storage.audit import init_audit
from app.storage.deployments import init_deployments
from app.storage.entities import init_entities
from app.storage.governance_policy import init_governance_policy
from app.storage.incidents import init_incidents
from app.storage.intake import init_intake
from app.storage.lifecycle import init_lifecycle
from app.storage.organizations import init_organizations
from app.storage.prompts import init_prompts
from app.storage.raw_events import init_storage
from app.storage.workflow import init_workflow

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
seed_super_admin()
app.include_router(ingestion_router)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(intake_router)
app.include_router(api_router)
app.include_router(compliance_router)

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
