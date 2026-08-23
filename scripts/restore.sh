#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into the running PostgreSQL.
# Usage: scripts/restore.sh backups/norinth-<timestamp>.sql.gz
# This REPLACES the current database contents.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <backup.sql.gz>" >&2; exit 2; }
cd "$(dirname "$0")/.."
DUMP="$1"

# Validate the dump BEFORE dropping anything: a missing, empty, or truncated
# archive must never cost the current database (audit finding H16).
[ -f "$DUMP" ] || { echo "error: backup file not found: $DUMP" >&2; exit 1; }
[ -s "$DUMP" ] || { echo "error: backup file is empty: $DUMP" >&2; exit 1; }
gunzip -t "$DUMP" || { echo "error: backup file is not a valid gzip archive: $DUMP" >&2; exit 1; }

read -r -p "This replaces the current Norinth database with $DUMP. Type 'restore' to confirm: " a
[ "$a" = restore ] || { echo "Aborted."; exit 1; }

docker compose stop norinth
docker compose exec -T postgres psql -U norinth -d postgres -c "DROP DATABASE IF EXISTS norinth;" -c "CREATE DATABASE norinth OWNER norinth;"

# ON_ERROR_STOP makes psql abort (non-zero) on the first failed statement, so a
# partial restore fails loudly instead of leaving a half-populated database and
# still reporting success. On failure the DB is left empty and norinth stays
# stopped for the operator to investigate.
if ! gunzip -c "$DUMP" | docker compose exec -T postgres psql -U norinth -d norinth -q -v ON_ERROR_STOP=1; then
  echo "error: restore failed partway through; the norinth database is now empty." >&2
  echo "The norinth service was left stopped. Investigate the dump and re-run." >&2
  exit 1
fi

docker compose start norinth
echo "Restored. Norinth restarted; migrations (if any) ran on boot."
