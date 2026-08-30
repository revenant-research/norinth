# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Revenant Research

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.admin import router as admin_router
from app.api.agents import router as agents_router
from app.api.attestation_keys import router as attestation_keys_router
from app.api.auth import router as auth_router
from app.api.compliance import router as compliance_router
from app.api.ingestion_keys import router as ingestion_keys_router
from app.api.intake import router as intake_router
from app.api.notifications import router as notifications_router
from app.api.onboarding import router as onboarding_router
from app.api.routes import router as api_router
from app.api.saml import router as saml_router
from app.api.scim import router as scim_router
from app.api.setup import router as setup_router
from app.api.sso import router as sso_router
from app.dashboard.html import dashboard_html
from app.dependencies import SESSION_COOKIE
from app.ingestion.routes import router as ingestion_router
from app.services.auth import resolve_session
from app.services.bootstrap import seed_dev_ingestion_key_if_dev, seed_super_admin
from app.services.maintenance import start_worker as start_maintenance_worker
from app.services.notifications import start_worker as start_notification_worker
from app.storage.errors import RecordNotFound
from app.storage.migrations import run_migrations
from app.storage.workflow import load_platform_user

# level via NORINTH_LOG_LEVEL, default INFO. NORINTH_LOG_JSON=1 emits one json
# object per line (with request ids and any structured extras) for log shippers
_LOG_JSON = os.getenv("NORINTH_LOG_JSON", "0").lower() in {"1", "true", "yes"}
logging.basicConfig(
    level=os.getenv("NORINTH_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
if _LOG_JSON:
    from app.services.observability import JsonLogFormatter

    for _handler in logging.getLogger().handlers:
        _handler.setFormatter(JsonLogFormatter())

STATIC_DIR = Path(__file__).resolve().parent / "dashboard" / "static"
ASSETS_DIR = STATIC_DIR / "assets"
INDEX_FILE = STATIC_DIR / "index.html"

app = FastAPI(title="Norinth Platform", description="AI governance platform API: ingestion, inventory, risk, review workflow, release gates, compliance evidence.")

# host-header trust is checked only where saml/oidc build callback urls (see
# services/base_url.py), not globally: a global check would 400 health probes
# that arrive with a localhost or pod-ip host

def _validate_secret_key_at_startup() -> None:
    """fail fast on a malformed NORINTH_SECRET_KEY

    the key is used both as a raw HMAC key (any bytes) and, base64-decoded, as a
    32-byte AES key for secret encryption. a key that is set but not valid
    32-byte base64 lets the platform boot and pass health checks, then 500s the
    first time a secret is written (a webhook or SSO config). validate it here so
    the misconfiguration surfaces at startup with a clear message
    """
    if not os.getenv("NORINTH_SECRET_KEY"):
        return
    from app.services.secrets import SecretKeyMissing, master_key

    try:
        master_key()
    except SecretKeyMissing as error:
        raise RuntimeError(
            f"NORINTH_SECRET_KEY is set but invalid: {error}. It must be 32 bytes, "
            "base64-encoded (generate one with: openssl rand -base64 32)."
        ) from error


_validate_secret_key_at_startup()
run_migrations()
start_notification_worker()
start_maintenance_worker()


def _outbox_pending() -> float:
    from app.storage.raw_events import connect

    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS n FROM notification_outbox WHERE status = 'pending'"
        ).fetchone()
    return float(row["n"])


# scrape-time gauge: the outbox is small by design (delivered rows age out),
# so the count is cheap, and a growing value is the earliest sign deliveries
# are failing
from app.services.observability import gauge_callback  # noqa: E402

gauge_callback("norinth_outbox_pending", "Notification outbox rows awaiting delivery", _outbox_pending)
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
app.include_router(saml_router)
app.include_router(scim_router)
app.include_router(agents_router)
app.include_router(attestation_keys_router)
app.include_router(onboarding_router)
app.include_router(setup_router)
app.include_router(notifications_router)

@app.exception_handler(RecordNotFound)
async def _record_not_found_handler(request: Request, exc: RecordNotFound):
    return JSONResponse(status_code=404, content={"detail": str(exc) or "Not found"})


@app.exception_handler(ValueError)
async def _value_error_handler(request: Request, exc: ValueError):
    # domain ValueErrors are bad input, return 400 not a 500/stack trace
    return JSONResponse(status_code=400, content={"detail": str(exc) or "Invalid request"})


# reachable while a user still owes a password change
_PASSWORD_CHANGE_ALLOWLIST = {
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/api/auth/change-password",
    "/api/auth/sso/callback",
    "/api/auth/saml/acs",
    "/api/auth/saml/metadata",
    "/api/setup/state",
    "/api/auth/accept-invite",
}


_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# saml acs is a cross-site form post from the idp by design; protected by the
# assertion signature and InResponseTo binding, not by origin matching
_CSRF_EXEMPT = {"/api/auth/saml/acs"}


_access_logger = logging.getLogger("norinth.access")


@app.middleware("http")
async def request_telemetry(request: Request, call_next):
    """request id + http metrics + (in json mode) one access-log line

    the id arrives on X-Request-ID or is minted here, follows the request
    through a contextvar so every log line carries it, and returns on the
    response so a caller can quote it in a support ticket. the metric route
    label is the route TEMPLATE (/api/applications/{application_id}), never
    the raw path, so label cardinality stays bounded
    """
    from app.services import observability

    request_id = observability.new_request_id(request.headers.get("x-request-id"))
    token = observability.request_id_var.set(request_id)
    timer = observability.Timer()
    try:
        with timer:
            response = await call_next(request)
    finally:
        observability.request_id_var.reset(token)
    route = getattr(request.scope.get("route"), "path", None)
    if route:  # unknown paths (404 scans) share one label instead of minting new ones
        observability.counter_inc(
            "norinth_http_requests_total",
            "HTTP requests by method, route template and status class",
            {"method": request.method, "route": route, "status": f"{response.status_code // 100}xx"},
        )
        observability.histogram_observe(
            "norinth_http_request_duration_seconds",
            "HTTP request duration by route template",
            timer.elapsed,
            {"route": route},
        )
    else:
        observability.counter_inc(
            "norinth_http_requests_total",
            "HTTP requests by method, route template and status class",
            {"method": request.method, "route": "unmatched", "status": f"{response.status_code // 100}xx"},
        )
    response.headers["X-Request-ID"] = request_id
    if _LOG_JSON:
        _access_logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round(timer.elapsed * 1000, 2),
            },
        )
    return response


@app.get("/metrics")
def metrics(request: Request):
    """prometheus scrape endpoint — operator plane, never anonymous

    a bearer token (NORINTH_METRICS_TOKEN) authenticates scrapers; a platform
    administrator session also works for a human look. metric labels include
    tenant ids, which is exactly why this is not public
    """
    from fastapi.responses import PlainTextResponse

    from app.services.observability import render_metrics

    token = os.getenv("NORINTH_METRICS_TOKEN")
    supplied = request.headers.get("authorization", "")
    if token and supplied == f"Bearer {token}":
        return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4")
    user_ref = resolve_session(request.cookies.get(SESSION_COOKIE))
    if user_ref:
        user = load_platform_user(user_ref)
        if user and user.get("platform_role") == "super_admin":
            return PlainTextResponse(render_metrics(), media_type="text/plain; version=0.0.4")
    return JSONResponse(status_code=403, content={"detail": "Metrics require NORINTH_METRICS_TOKEN or a platform administrator session"})


@app.middleware("http")
async def csrf_origin_check(request: Request, call_next):
    """csrf origin check for cookie-authed mutations

    browsers forbid scripts from forging Origin, so requiring it to match the
    request host on mutating /api/* calls blocks csrf. requests without an Origin
    (non-browser clients, no ambient cookies) are unaffected. /v1/* uses key
    auth, out of scope. complements the cookie's SameSite=lax
    """
    if (
        request.method in _MUTATING_METHODS
        and request.url.path.startswith("/api/")
        and request.url.path not in _CSRF_EXEMPT
    ):
        origin = request.headers.get("origin")
        if origin:
            # behind a tls-terminating proxy the request scheme is http while the
            # browser Origin is https; honour x-forwarded-proto/host when a trusted
            # proxy is declared so logins are not all 403'd. compare scheme+host+port
            trust_proxy = os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}
            scheme = request.url.scheme
            host = request.headers.get("host", "")
            if trust_proxy:
                scheme = (request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip()) or scheme
                host = (request.headers.get("x-forwarded-host", host).split(",")[0].strip()) or host
            expected = {f"{scheme}://{host}"}
            # also accept the configured public url if set
            public = os.getenv("NORINTH_PUBLIC_BASE_URL")
            if public:
                expected.add(public.rstrip("/"))
            if origin.rstrip("/") not in {e.rstrip("/") for e in expected}:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Cross-origin request rejected"},
                )
    return await call_next(request)


@app.middleware("http")
async def enforce_password_change(request: Request, call_next):
    """block a must_change_password user from anything but the auth allowlist

    frontend-only enforcement would let a temporary password drive the whole api
    via curl. /v1/... uses key auth and is unaffected
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


# swagger/redoc docs pull third-party scripts the strict csp would block; these
# routes carry no tenant data so exempt them from csp
_CSP_EXEMPT_PREFIXES = ("/docs", "/redoc", "/openapi.json")

_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


# reject oversized bodies before reading so one huge payload can't exhaust memory
# override with NORINTH_MAX_BODY_BYTES; 0 disables
_MAX_BODY_BYTES = int(os.getenv("NORINTH_MAX_BODY_BYTES", str(16 * 1024 * 1024)))


class BodySizeLimitMiddleware:
    """cap the request body at the byte level, not the declared Content-Length

    checking only the Content-Length header lets a chunked request (which omits
    it) stream an unbounded body into memory. this counts the bytes as they
    arrive and rejects at the cap, so memory stays bounded whatever the client
    declares. a body within the cap is buffered and replayed to the app
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if self.max_bytes <= 0 or scope.get("type") != "http" or scope.get("method") not in _MUTATING_METHODS:
            await self.app(scope, receive, send)
            return

        # honest oversize Content-Length is rejected without reading the body
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await self._reject(send, 413, "Request body too large")
                        return
                except ValueError:
                    await self._reject(send, 400, "Invalid Content-Length")
                    return
                break

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                break
            body.extend(message.get("body", b""))
            more_body = message.get("more_body", False)
            if len(body) > self.max_bytes:
                while more_body:  # drain the rest so the client is not left hanging
                    drained = await receive()
                    if drained["type"] == "http.disconnect":
                        break
                    more_body = drained.get("more_body", False)
                await self._reject(send, 413, "Request body too large")
                return

        buffered = bytes(body)
        replayed = False

        async def replay():
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": buffered, "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})


app.add_middleware(BodySizeLimitMiddleware, max_bytes=_MAX_BODY_BYTES)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """hardening response headers

    hsts only when the effective scheme is https (directly or via trusted proxy)
    so plain-http dev is not pinned
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    if not request.url.path.startswith(_CSP_EXEMPT_PREFIXES):
        response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)

    scheme = request.url.scheme
    if os.getenv("NORINTH_TRUST_PROXY", "0").lower() in {"1", "true", "yes"}:
        scheme = (request.headers.get("x-forwarded-proto", scheme).split(",")[0].strip()) or scheme
    if scheme == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="platform-assets")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    if INDEX_FILE.exists():
        return HTMLResponse(
            INDEX_FILE.read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
    return HTMLResponse(dashboard_html(str(STATIC_DIR)), status_code=503)
