# Operating Norinth

Norinth is a single stateless web service (FastAPI + the compiled dashboard)
in front of a PostgreSQL database. That is the whole system. This guide covers
installing it, running it in production, configuring it, backing it up, and
upgrading it.

## 1. Install

### One command (laptop, VM)

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash
```

The script checks for Docker (and offers to install it on Ubuntu/Debian),
creates `./norinth`, writes a `.env` with generated secrets (PostgreSQL
password, `NORINTH_SECRET_KEY`, administrator password), pulls the image, starts
PostgreSQL and Norinth, waits for `/health`, and prints the URL and login.

Flags: `--dir PATH`, `--port N`, `--source` (build from a checkout instead of
pulling the image), `--upgrade`, `--uninstall`, `--yes`. Re-running never
overwrites an existing `.env`.

From a checkout: `make docker-up` (equivalent to `scripts/install.sh --source --dir . --yes`).

### Kubernetes

```bash
helm install norinth oci://ghcr.io/revenant-research/charts/norinth \
  --set database.url='postgresql://norinth:PASSWORD@postgres.internal:5432/norinth' \
  --set secrets.secretKey="$(openssl rand -base64 32)" \
  --set secrets.superAdminPassword="$(openssl rand -base64 24)" \
  --set config.publicBaseUrl=https://norinth.example.com \
  --set ingress.enabled=true --set ingress.hosts[0].host=norinth.example.com
```

The chart (`deploy/helm/norinth`) renders a stateless Deployment, Service,
Ingress, PodDisruptionBudget and Secrets; use `database.existingSecret` /
`secrets.existingSecret` to source secrets from Vault, External Secrets or
SealedSecrets. Images are signed (cosign keyless) with an SBOM attestation;
verify before you trust:

```bash
cosign verify ghcr.io/revenant-research/norinth:<version> \
  --certificate-identity-regexp 'https://github.com/revenant-research/norinth/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The files attached to each GitHub Release (installer, compose file, SBOM,
SDK wheel and source distribution) come with `SHA256SUMS`, a Sigstore
signature of that file, and SLSA build provenance for every file. Check a
download before you run it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify install.sh --repo revenant-research/norinth
```

`gh attestation verify` fetches the attestation from GitHub; pass
`--bundle norinth-<version>.sigstore.json` to verify against the copy attached
to the release instead. `norinth-<version>.intoto.jsonl` is the same
attestation as a bare in-toto envelope for tools that read that format.

### Requirements

- Docker 24+ with the compose plugin (or any OCI runtime).
- Modest resources for evaluation (the platform is a single Python process); size PostgreSQL to your event volume.
- PostgreSQL 14+ for production. SQLite is for local evaluation only.
- Python 3.11+ where the SDK runs.

## 2. First run

The first visit opens the setup wizard: claim the administrator account, name
your organization and its first administrator, create an ingestion key, paste
the snippet into one application, and watch the first event arrive. After that,
**Getting started** inside the product lists what remains (reviewers, owners,
signed evidence, identity provider, first audit packet).

## 3. Configuration reference

All configuration is by environment variable. Secrets should come from your
secret manager; the installer writes them to `.env` for Compose.

| Variable | Required | Default | What it does |
|---|---|---|---|
| `NORINTH_DATABASE_URL` | production | — | PostgreSQL URL (`postgresql://user:pass@host:5432/norinth`). When set, SQLite is ignored. |
| `NORINTH_PLATFORM_DB` | no | `apps/platform/data/norinth.sqlite3` | SQLite path for local evaluation only. |
| `NORINTH_SECRET_KEY` | production | — | 32-byte base64 master key for AES-256-GCM encryption of stored integration secrets (OIDC client secrets, etc.). Rotating it requires re-entering those secrets. |
| `NORINTH_SUPER_ADMIN_EMAIL` | no | `admin@norinth.local` | Bootstrap platform administrator. |
| `NORINTH_SUPER_ADMIN_PASSWORD` | production | dev default | Bootstrap password. When unset the platform runs in **development mode**: a documented default password with forced rotation and a well-known `dev` ingestion key. Never leave unset outside a laptop. |
| `NORINTH_PUBLIC_BASE_URL` | with SSO | request host | Public URL used to build OIDC redirect URIs and SAML SP metadata/ACS URLs. |
| `NORINTH_COOKIE_SECURE` | behind TLS | auto | `1` marks the session cookie Secure. Defaults on when not in development mode. |
| `NORINTH_TRUST_PROXY` | behind a proxy | `0` | `1` reads the client IP from `X-Forwarded-For` for login throttling. Only set when your ingress overwrites that header. |
| `NORINTH_SESSION_TTL_HOURS` | no | `12` | Absolute session lifetime. |
| `NORINTH_SESSION_IDLE_MINUTES` | no | `30` | Idle timeout: a session with no request for this long is ended, regardless of remaining absolute lifetime. `0` disables. |
| `NORINTH_SIGNING_SECRET` | no | — | Optional shared HMAC secret; when set, `/v1/events/batch` additionally requires `X-Norinth-Signature`. Per-tenant ingestion keys are the primary control. |
| `NORINTH_LOGIN_LOCKOUT_THRESHOLD` / `_WINDOW_MINUTES` / `_MINUTES` | no | `5` / `15` / `15` | Per-account failed-login throttling. |
| `NORINTH_LOGIN_IP_THRESHOLD` / `_WINDOW_MINUTES` / `_LOCKOUT_MINUTES` | no | `50` / `15` / `15` | Per-source-IP throttling (higher: shared NATs). |
| `NORINTH_DEV_INGEST_TENANT` | no | `tenant-local` | Tenant bound to the dev `dev` key (development mode only). |
| `NORINTH_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_STARTTLS` | for email | — / `587` / — / — / user / `1` | Outbound email for invites and notifications (review assigned/overdue/escalated, gate decisions, incidents). Without a host, emails are recorded as `skipped_no_smtp` in the delivery log and invite links are shown to the administrator instead. |
| `NORINTH_LOG_JSON` | no | `0` | `1` emits one JSON object per log line (timestamp, level, logger, message, request id, structured fields) for log shippers. Every audit-chain append is also streamed to the `norinth.audit` logger, so a SIEM sees security events without polling the database. |
| `NORINTH_METRICS_TOKEN` | for scraping | — | Bearer token for `GET /metrics` (Prometheus text format: request rates/latency by route, accepted events per tenant, audit-append duration, outbox depth). Without it, only a platform administrator session can read metrics — the endpoint is never anonymous, because labels include tenant ids. |
| `NORINTH_NOTIFICATIONS_WORKER` | no | `1` | `0` disables the background delivery thread (tests). |
| `NORINTH_MAINTENANCE_WORKER` | no | `1` | `0` disables the governance maintenance thread. It lapses expired exceptions and ages the review queue (overdue, escalated) on a timer, so those transitions do not wait for the next batch of telemetry. Leave it on unless you schedule the work yourself. |
| `NORINTH_MAINTENANCE_INTERVAL_SECONDS` | no | `300` | Seconds between maintenance passes. On PostgreSQL a try-lock keeps concurrent replicas from running a pass at the same time. |

### Telemetry retention

Each organization sets its own retention window under **Settings → retention**, or
`POST /api/retention-policy` with `{"retention_days": 90}`. The maintenance worker
then deletes that organization's raw events once they pass the window. A window of
`null` — the default, including after an upgrade — keeps everything, so no install
starts deleting because it was upgraded. The floor is 7 days; shorter values are
rejected rather than honoured, because the deletion cannot be undone.

Only raw events are aged out. Derived governance records (inventory, findings,
assessments, decisions, gates) are kept, and the audit log is never purged: deleting
from it would break the hash chain that proves its integrity. Every purge is written
to the audit log with the number of events deleted.

Offboarding an organization entirely is a separate, irreversible operation
(`POST /api/admin/organizations/{tenant_id}/purge`, super administrator, requires
`confirm_tenant_id`). The one-off operator equivalent of a retention sweep is
`POST /api/admin/retention/purge-events`, which requires an explicit `tenant_id` or
`all_tenants: true`.

SDK-side variables (in your applications): `NORINTH_API_KEY`, `NORINTH_ENDPOINT`,
`NORINTH_PROJECT`, `NORINTH_ENVIRONMENT`, `NORINTH_SERVICE`,
`NORINTH_APPLICATION_NAME`, `NORINTH_USE_CASE`, `NORINTH_MODE`,
`NORINTH_CAPTURE_CONTENT` (off by default; prompts, completions and `metadata`
values are hashed), `NORINTH_METADATA_ALLOWLIST` (extra metadata keys to keep in
the clear), `NORINTH_CAPTURE_INCIDENT_DETAILS` (off by default; incident
descriptions are hashed), `NORINTH_SPOOL_DIR` (where undelivered batches wait; a
private per-service directory under `$XDG_STATE_HOME`, `~/.local/state` or the
temp directory by default, `off` to disable) and `NORINTH_DURABLE` (refuse to
start without a spool, for deployments treating telemetry as evidence). The
SDK logs one warning at startup whenever it has no spool. Each `sdk.health`
event carries `durable`, `spool_configured` and the `dropped` and `spooled`
counters, and the platform raises the risk finding `RISK-EVD-001` (Evidence
delivery is not durable) against an application whose SDK reports no spool or
a dropped batch. See `packages/python-sdk/README.md`.

Raw event bodies are encrypted at rest whenever `NORINTH_SECRET_KEY` /
`NORINTH_SECRET_KEYS` is configured. Set `NORINTH_ENCRYPT_RAW_EVENTS=0` to opt
out deliberately (for example to keep the column queryable); a keyless install
stores plaintext because encryption fails closed without a key.

## 4. Connecting your identity provider

Set `NORINTH_PUBLIC_BASE_URL` to the URL your users reach Norinth on before you
start. The redirect URI, SAML entity ID and ACS URL are all built from it, and an
identity provider rejects a login whose URLs do not match what you registered.

Everything below is configured by an **organization administrator**, inside the
organization, under Identity & Integrations. Each organization connects its own
provider; there is no platform-wide identity configuration.

### OpenID Connect (Okta, Entra ID, Auth0, Keycloak)

Register Norinth as a web application in your provider and give it this redirect
URI, substituting your own host:

```
https://norinth.example.com/api/auth/sso/callback
```

Then in Norinth, `POST /api/org/sso` (or the Identity & Integrations screen) with
the `issuer`, `client_id` and `client_secret` your provider issued. Two optional
fields are worth setting: `allowed_email_domain` refuses sign-ins from outside
your domain, and `default_role` is the role a first-time user is provisioned with
(`governance_viewer` unless you change it).

Users sign in at `/api/auth/sso/<your-organization-id>/start`.

Just-in-time provisioning creates a user on first successful sign-in. It never
grants an administration role, whatever the provider asserts, and a user created
this way cannot fall back to a local password.

### SAML 2.0

Import the service-provider metadata into your identity provider:

```
https://norinth.example.com/api/auth/saml/metadata
```

It declares the entity ID (the metadata URL itself), the assertion consumer
service at `/api/auth/saml/acs` over HTTP-POST, an `emailAddress` NameID, and
that assertions must be signed. Norinth does not sign authentication requests.

In Norinth, configure the organization with your provider's SSO URL, entity ID
and signing certificate in PEM form. Users sign in at
`/api/auth/saml/<your-organization-id>/start`.

Assertions are rejected unless the signature verifies against the certificate you
configured, the audience and recipient match the URLs above, the assertion is
inside its validity window, and it answers an authentication request this browser
actually started. A replayed or rewritten `InResponseTo` is refused.

### SCIM 2.0 provisioning

Create a token under Identity & Integrations (`POST /api/org/scim-tokens`). It is
shown once, is prefixed `nrs_`, and is scoped to the organization that made it.

Point your provider at:

```
Base URL: https://norinth.example.com/scim/v2
Token:    the nrs_… value, sent as `Authorization: Bearer`
```

`/scim/v2/Users` supports create, read, replace, patch and delete. Unlike the
usual SCIM discovery convention, `/scim/v2/ServiceProviderConfig` requires the
token as well, so a provider that probes it anonymously will see a 401.

What earns SCIM its place is the leaver case: deactivating a user through SCIM
also revokes their live sessions, so access ends when your directory says it
does rather than whenever their session happens to expire.

## 5. Networking and endpoints

| Path | Auth | Purpose |
|---|---|---|
| `/` , `/assets/*` | none | Dashboard |
| `/health` | none | Liveness (`{"ok": true}`) |
| `/api/*` | session cookie (+ Origin check on mutations) | Platform API; OpenAPI at `/docs` |
| `/v1/events/batch`, `/v1/otel/traces` | `Authorization: Bearer nrk_…` | Ingestion |
| `/scim/v2/*` | `Authorization: Bearer nrs_…` | SCIM provisioning |
| `/api/auth/sso/*`, `/api/auth/saml/*` | IdP redirect | SSO |
| `/api/public/leads` | none (rate-limited) | Landing page contact form |

Terminate TLS at your load balancer or ingress; set `NORINTH_PUBLIC_BASE_URL`,
`NORINTH_COOKIE_SECURE=1`, `NORINTH_TRUST_PROXY=1`. Ingestion endpoints are
the only ones applications need to reach; the dashboard and SCIM can be
restricted to your corporate network.

## 6. Backup and restore

```bash
scripts/backup.sh                                   # -> backups/norinth-<utc>.sql.gz
scripts/restore.sh backups/norinth-<utc>.sql.gz     # replaces the database, restarts Norinth
```

Everything Norinth knows is in PostgreSQL (events, entities, decisions, the
hash-chained audit log, encrypted integration secrets). Back up `.env` too:
without `NORINTH_SECRET_KEY` the stored integration secrets cannot be decrypted.
With a managed PostgreSQL, use its point-in-time recovery instead.

## 7. Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash -s -- --upgrade --dir ./norinth
# or: cd norinth && docker compose pull && docker compose up -d
```

Schema changes are versioned migrations (`apps/platform/app/storage/migrations.py`)
applied on boot and recorded in `schema_migrations`; Console → Overview shows
the applied versions. Migrations are forward-only: take a backup first.
Releases follow semantic versioning; the changelog lists breaking changes.

### Audit integrity at startup

Startup verifies audit history before starting background workers. A failed
check stops startup and preserves the rows for investigation; missing HMACs are
never regenerated. Configure signing keys before collecting audit history and
retain old verification keys during rotation. An empty database needs no setup
beyond key configuration. Investigate failed checks rather than re-signing rows.

## 8. Sizing and performance

Scale **replicas first, workers second**: `NORINTH_WEB_CONCURRENCY` sets
uvicorn workers per container (default 1; the Compose file and Helm chart set
2). More than one worker requires PostgreSQL — worker processes contend on a
SQLite file, while the notification-outbox claims, migration coordination and
the audit advisory lock are already multi-worker safe on PostgreSQL.

PostgreSQL connections are pooled per process (`NORINTH_PG_POOL_SIZE`,
default 10; `0` restores a connection per call). Idle pooled connections are
discarded after `NORINTH_PG_POOL_MAX_IDLE_SECONDS` (default 300) so a
server-side idle timeout or database restart never hands out a dead socket.

Measure your own deployment with the included harness against a disposable
tenant key:

```bash
python scripts/loadtest.py --endpoint https://norinth.internal --key nrk_... \
    --tenant your-tenant --batches 200 --events-per-batch 25 --concurrency 8
```

Indicative numbers from a development laptop (M-series, PostgreSQL 14 on the
same machine, encryption at rest on, 2 workers): sustained **~200 accepted
events/second** (≈17M/day) at 25-event batches with zero errors; direct
per-batch ingest cost ~48 ms on an empty database and ~80 ms at 3,000 stored
events per application — the residual growth is a handful of indexed
aggregate queries, and per-application history is bounded in practice by the
retention window. Connection pooling alone removes ~30% of per-batch cost.
For reference, 50,000 events/day is ~0.6 events/second sustained.

## 9. Hardening checklist

- `NORINTH_SUPER_ADMIN_PASSWORD` and `NORINTH_SECRET_KEY` set (never development mode).
- TLS everywhere; `NORINTH_COOKIE_SECURE=1`; `NORINTH_TRUST_PROXY=1` only behind a header-rewriting proxy.
- PostgreSQL on a private network with its own credentials; encrypted at rest.
- Restrict `/`, `/api`, `/scim` to your network; expose `/v1/*` only where applications live.
- Connect SSO and SCIM so joiner/leaver control is automatic; keep local passwords for break-glass only.
- Every local-password account — the platform administrator included — can enroll TOTP MFA
  under **Security** in the header (any authenticator app; no external service). Once enrolled,
  a password alone (including one reset by an operator) cannot open the account. Users get ten
  single-use recovery codes at enrollment; an organization administrator can reset a locked-out
  member's MFA, the platform operator cannot. Keep at least two organization administrators so
  an MFA reset is always available in-tenant.
- Organizations can **require** MFA (People & access → Security policy). Turning it on never
  locks anyone out: unenrolled members keep their password login but reach only the enrollment
  screen until a second factor is active. SSO/SCIM-provisioned accounts are exempt — their
  factor lives at your identity provider — and the administrator flipping the switch must
  already be enrolled themselves.
- Register an attestation key so release gates require CI-signed evaluation evidence.
- Schedule `scripts/backup.sh`; test `restore.sh` once.
- Verify the audit chain periodically: `GET /api/admin/audit-logs/verify`.

## 10. Notifications

Email (SMTP) and signed webhooks. Organization administrators add webhooks
under Identity & Integrations → Notifications: JSON for SIEM/ticketing or
Slack incoming-webhook format, per-event selection, a signing secret shown
once. Every delivery is `POST` with `X-Norinth-Event`, `X-Norinth-Delivery`
and `X-Norinth-Signature: sha256=<HMAC-SHA256(secret, body)>`. Failed
deliveries retry with exponential backoff (up to six attempts); the delivery
log shows every outcome.

Events: `user.invited`, `review.assigned`, `review.overdue`,
`review.escalated`, `gate.approved`, `gate.rejected`, `incident.opened`,
`incident.closed`.

## 11. Observability

`/health` for liveness. Application logs go to stdout (uvicorn). The platform
itself emits no telemetry to anyone.
