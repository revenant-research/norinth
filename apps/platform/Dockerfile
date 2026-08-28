# syntax=docker/dockerfile:1

# ---- Stage 1: build the dashboard bundle from source -------------------------
# The compiled bundle is a build artifact (not committed), so it is built from
# source in the image and reviewers never have to trust a minified blob. Base
# images are pinned by digest as well as tag: a tag is mutable, so tag-only pins
# mean the image audited is not necessarily the image shipped. The tag is kept
# alongside for readability. Refresh both together when bumping a base image.
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend
WORKDIR /src/frontend
COPY apps/platform/frontend/package.json apps/platform/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/platform/frontend/ ./
# vite.config.ts emits to ../app/dashboard/static, i.e. /src/app/dashboard/static
RUN npm run build

# ---- Stage 2: runtime ----------------------------------------------------------
FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

# Non-root runtime user
RUN groupadd --system norinth && useradd --system --gid norinth --home /app norinth

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    NORINTH_PLATFORM_DB=/app/data/norinth.sqlite3

# Install dependencies (path is relative to the build context = repo root).
# The lock file pins every transitive dependency to an exact version and hash, so
# the image contents follow from the repo rather than from whatever the index
# served that day. --require-hashes makes a tampered or substituted artifact a
# build failure instead of a silent swap. Regenerate with `make lock`.
COPY apps/platform/requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

# Application code, then the freshly built dashboard bundle on top
COPY apps/platform/app /app/app
COPY --from=frontend /src/app/dashboard/static /app/app/dashboard/static

# Data directory for the SQLite database, owned by the runtime user
RUN mkdir -p /app/data && chown -R norinth:norinth /app

USER norinth

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3).status==200 else 1)"

# NORINTH_WEB_CONCURRENCY > 1 requires PostgreSQL: worker processes contend on
# a sqlite file, while the outbox claims, migration coordination and the audit
# advisory lock are already multi-worker safe on postgres
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers ${NORINTH_WEB_CONCURRENCY:-1}"]
