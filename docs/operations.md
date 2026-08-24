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
| `NORINTH_SESSION_TTL_HOURS` | no | `12` | Session lifetime. |
| `NORINTH_SIGNING_SECRET` | no | — | Optional shared HMAC secret; when set, `/v1/events/batch` additionally requires `X-Norinth-Signature`. Per-tenant ingestion keys are the primary control. |
| `NORINTH_LOGIN_LOCKOUT_THRESHOLD` / `_WINDOW_MINUTES` / `_MINUTES` | no | `5` / `15` / `15` | Per-account failed-login throttling. |
| `NORINTH_LOGIN_IP_THRESHOLD` / `_WINDOW_MINUTES` / `_LOCKOUT_MINUTES` | no | `50` / `15` / `15` | Per-source-IP throttling (higher: shared NATs). |
| `NORINTH_DEV_INGEST_TENANT` | no | `tenant-local` | Tenant bound to the dev `dev` key (development mode only). |
| `NORINTH_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_STARTTLS` | for email | — / `587` / — / — / user / `1` | Outbound email for invites and notifications (review assigned/overdue/escalated, gate decisions, incidents). Without a host, emails are recorded as `skipped_no_smtp` in the delivery log and invite links are shown to the administrator instead. |
| `NORINTH_NOTIFICATIONS_WORKER` | no | `1` | `0` disables the background delivery thread (tests). |
| `NORINTH_MAINTENANCE_WORKER` | no | `1` | `0` disables the governance maintenance thread. It lapses expired exceptions and ages the review queue (overdue, escalated) on a timer, so those transitions do not wait for the next batch of telemetry. Leave it on unless you schedule the work yourself. |
| `NORINTH_MAINTENANCE_INTERVAL_SECONDS` | no | `300` | Seconds between maintenance passes. On PostgreSQL a try-lock keeps concurrent replicas from running a pass at the same time. |

SDK-side variables (in your applications): `NORINTH_API_KEY`, `NORINTH_ENDPOINT`,
`NORINTH_PROJECT`, `NORINTH_ENVIRONMENT`, `NORINTH_SERVICE`,
`NORINTH_APPLICATION_NAME`, `NORINTH_USE_CASE`, `NORINTH_MODE`,
`NORINTH_CAPTURE_CONTENT` (off by default; prompts and completions are hashed).
See `packages/python-sdk/README.md`.

## 4. Networking and endpoints

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

## 5. Backup and restore

```bash
scripts/backup.sh                                   # -> backups/norinth-<utc>.sql.gz
scripts/restore.sh backups/norinth-<utc>.sql.gz     # replaces the database, restarts Norinth
```

Everything Norinth knows is in PostgreSQL (events, entities, decisions, the
hash-chained audit log, encrypted integration secrets). Back up `.env` too:
without `NORINTH_SECRET_KEY` the stored integration secrets cannot be decrypted.
With a managed PostgreSQL, use its point-in-time recovery instead.

## 6. Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/revenant-research/norinth/main/scripts/install.sh | bash -s -- --upgrade --dir ./norinth
# or: cd norinth && docker compose pull && docker compose up -d
```

Schema changes are versioned migrations (`apps/platform/app/storage/migrations.py`)
applied on boot and recorded in `schema_migrations`; Console → Overview shows
the applied versions. Migrations are forward-only: take a backup first.
Releases follow semantic versioning; the changelog lists breaking changes.

## 7. Hardening checklist

- `NORINTH_SUPER_ADMIN_PASSWORD` and `NORINTH_SECRET_KEY` set (never development mode).
- TLS everywhere; `NORINTH_COOKIE_SECURE=1`; `NORINTH_TRUST_PROXY=1` only behind a header-rewriting proxy.
- PostgreSQL on a private network with its own credentials; encrypted at rest.
- Restrict `/`, `/api`, `/scim` to your network; expose `/v1/*` only where applications live.
- Connect SSO and SCIM so joiner/leaver control is automatic; keep local passwords for break-glass only.
- Register an attestation key so release gates require CI-signed evaluation evidence.
- Schedule `scripts/backup.sh`; test `restore.sh` once.
- Verify the audit chain periodically: `GET /api/admin/audit-logs/verify`.

## 8. Notifications

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

## 9. Observability

`/health` for liveness. Application logs go to stdout (uvicorn). The platform
itself emits no telemetry to anyone.
