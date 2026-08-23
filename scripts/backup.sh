#!/usr/bin/env bash
# Dump the Norinth PostgreSQL database to ./backups/norinth-<timestamp>.sql.gz
# Run from the install directory (where docker-compose.yml and .env live).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
out="backups/norinth-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
docker compose exec -T postgres pg_dump -U norinth -d norinth --no-owner | gzip > "$out"
echo "Backup written to $out ($(du -h "$out" | cut -f1))"
