#!/usr/bin/env bash
# Restore a backup produced by scripts/backup.sh into the running PostgreSQL.
# Usage: scripts/restore.sh backups/norinth-<timestamp>.sql.gz
# This REPLACES the current database contents.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <backup.sql.gz>" >&2; exit 2; }
cd "$(dirname "$0")/.."
DUMP="$1"

# accept either the compose plugin or the standalone binary
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "error: Docker Compose is required (either 'docker compose' or 'docker-compose')." >&2
  exit 1
fi

# validate the dump before dropping anything: a missing, empty, or truncated
# archive must never cost the current database
[ -f "$DUMP" ] || { echo "error: backup file not found: $DUMP" >&2; exit 1; }
[ -s "$DUMP" ] || { echo "error: backup file is empty: $DUMP" >&2; exit 1; }
gunzip -t "$DUMP" || { echo "error: backup file is not a valid gzip archive: $DUMP" >&2; exit 1; }
# an empty dump is still valid gzip; restoring it would drop the database and put
# nothing back, so check there is actually SQL in there before touching anything
sql_bytes=$(gunzip -c "$DUMP" | wc -c | tr -d ' ')
[ "$sql_bytes" -ge 100 ] || { echo "error: backup contains no SQL ($sql_bytes bytes): $DUMP" >&2; exit 1; }

read -r -p "This replaces the current Norinth database with $DUMP. Type 'restore' to confirm: " a
[ "$a" = restore ] || { echo "Aborted."; exit 1; }

checkpoint_seal=$(compose exec -T norinth python -c 'from app.storage.audit import verify_audit_chain; r=verify_audit_chain(); print(r.get("checkpoint", {}).get("seal", ""))')
if [ -n "$checkpoint_seal" ]; then
  echo "Retained pre-restore audit checkpoint seal: $checkpoint_seal"
  echo "Save this seal with the restore record; reconciliation requires it."
fi

compose stop norinth
compose exec -T postgres psql -U norinth -d postgres -c "DROP DATABASE IF EXISTS norinth;" -c "CREATE DATABASE norinth OWNER norinth;"

# ON_ERROR_STOP makes psql abort (non-zero) on the first failed statement, so a
# partial restore fails loudly instead of leaving a half-populated database and
# still reporting success. On failure the DB is left empty and norinth stays
# stopped for the operator to investigate.
if ! gunzip -c "$DUMP" | compose exec -T postgres psql -U norinth -d norinth -q -v ON_ERROR_STOP=1; then
  echo "error: restore failed partway through; the norinth database is now empty." >&2
  echo "The norinth service was left stopped. Investigate the dump and re-run." >&2
  exit 1
fi

if [ -n "$checkpoint_seal" ]; then
  echo "Database restored. Norinth remains stopped so the retained audit checkpoint journal can be reconciled."
  echo "Verify the restored audit chain, run scripts/reconcile_audit_checkpoint.py in the Norinth container with the pre-restore final seal and backup reason, then run: docker compose up -d norinth"
else
  compose start norinth
  echo "Database restored and Norinth restarted. No retained checkpoint was available, so audit-log completeness cannot be established."
fi
