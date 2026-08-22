# syntax=docker/dockerfile:1
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

# Copy application code (includes the pre-built dashboard bundle under app/dashboard/static)
COPY apps/platform/app /app/app

# Data directory for the SQLite database, owned by the runtime user
RUN mkdir -p /app/data && chown -R norinth:norinth /app

USER norinth

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
