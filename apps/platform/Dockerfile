# syntax=docker/dockerfile:1

# ---- Stage 1: build the dashboard bundle from source -------------------------
# The compiled bundle is a build artifact (not committed), so it is built from
# source in the image and reviewers never have to trust a minified blob. (The
# base images below are pinned by tag, not digest, so the build is repeatable
# from source but not bit-for-bit reproducible.)
FROM node:20-alpine AS frontend
WORKDIR /src/frontend
COPY apps/platform/frontend/package.json apps/platform/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/platform/frontend/ ./
# vite.config.ts emits to ../app/dashboard/static, i.e. /src/app/dashboard/static
RUN npm run build

# ---- Stage 2: runtime ----------------------------------------------------------
FROM python:3.11-slim

# Non-root runtime user
RUN groupadd --system norinth && useradd --system --gid norinth --home /app norinth

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    NORINTH_PLATFORM_DB=/app/data/norinth.sqlite3

# Install dependencies (path is relative to the build context = repo root)
COPY apps/platform/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code, then the freshly built dashboard bundle on top
COPY apps/platform/app /app/app
COPY --from=frontend /src/app/dashboard/static /app/app/dashboard/static

# Data directory for the SQLite database, owned by the runtime user
RUN mkdir -p /app/data && chown -R norinth:norinth /app

USER norinth

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
