#!/usr/bin/env bash
# Dump the Norinth PostgreSQL database to ./backups/norinth-<timestamp>.sql.gz
# Run from the install directory (where docker-compose.yml and .env live).
set -euo pipefail
cd "$(dirname "$0")/.."

# accept either the compose plugin or the standalone binary
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "error: Docker Compose is required (either 'docker compose' or 'docker-compose')." >&2
  exit 1
fi

mkdir -p backups
out="backups/norinth-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
tmp="$out.partial"
# dump to a partial file: a failed run must never leave something that looks
# like a backup, because restore.sh would accept it and drop the database first
trap 'rm -f "$tmp"' EXIT
compose exec -T postgres pg_dump -U norinth -d norinth --no-owner | gzip > "$tmp"

# an empty dump is the dangerous case: it is still valid gzip, so it passes a
# surface check while restoring to nothing
sql_bytes=$(gunzip -c "$tmp" | wc -c | tr -d ' ')
if [ "$sql_bytes" -lt 100 ]; then
  echo "error: pg_dump produced no output ($sql_bytes bytes); previous backups are untouched." >&2
  exit 1
fi

mv "$tmp" "$out"
trap - EXIT
echo "Backup written to $out ($(du -h "$out" | cut -f1), $sql_bytes bytes of SQL)"

# Keep a copy of the independently stored checkpoint journal beside the dump
# for disaster recovery. Never restore this copy over a newer retained journal:
# that would roll back the evidence used to detect a database truncation.
checkpoint_out="${out%.sql.gz}.audit-checkpoints.jsonl"
checkpoint_tmp="$checkpoint_out.partial"
if compose exec -T norinth cat /var/lib/norinth-audit-checkpoints/heads.jsonl > "$checkpoint_tmp" 2>/dev/null && [ -s "$checkpoint_tmp" ]; then
  mv "$checkpoint_tmp" "$checkpoint_out"
  echo "Checkpoint journal copied to $checkpoint_out; retain it on immutable/versioned storage."
else
  rm -f "$checkpoint_tmp"
  echo "Checkpoint journal unavailable; SQL backup alone cannot establish audit-log completeness." >&2
fi
