#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into the running PostgreSQL.
# Usage: scripts/restore.sh backups/norinth-<timestamp>.sql.gz
# This REPLACES the current database contents.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <backup.sql.gz>" >&2; exit 2; }
cd "$(dirname "$0")/.."
read -r -p "This replaces the current Norinth database with $1. Type 'restore' to confirm: " a
[ "$a" = restore ] || { echo "Aborted."; exit 1; }
docker compose stop norinth
docker compose exec -T postgres psql -U norinth -d postgres -c "DROP DATABASE IF EXISTS norinth;" -c "CREATE DATABASE norinth OWNER norinth;"
gunzip -c "$1" | docker compose exec -T postgres psql -U norinth -d norinth -q
docker compose start norinth
echo "Restored. Norinth restarted; migrations (if any) ran on boot."
