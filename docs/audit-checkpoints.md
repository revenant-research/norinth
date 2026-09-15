# Audit chain checkpoints

The audit chain verifier checks each surviving database row and its HMAC. A
valid surviving prefix alone cannot prove that the final rows were not deleted.
Set `NORINTH_AUDIT_CHECKPOINT_PATH` to a journal on storage separate from the
database. The Compose install uses `/var/lib/norinth-audit-checkpoints/heads.jsonl`
on the `norinth-audit-checkpoints` volume. Each committed audit append records
the epoch, count, head hash, time, signing key ID and previous checkpoint seal;
the journal is HMAC chained and fsynced. Keep the audit HMAC key outside the
database. Preserve old keys when rotating, or old rows and checkpoints cannot
be verified.

The database writer cannot edit the checkpoint volume. To protect the journal
against filesystem rollback or removal, replicate or snapshot it to versioned,
immutable storage with retention controlled separately from database access.
The local volume alone establishes a separate *database-write* trust boundary,
not protection against a host or volume administrator who can roll back both.
For Helm, set `auditCheckpoint.existingClaim` to a pre-existing ReadWriteMany
claim shared by all pods. The chart mounts that claim and sets
`NORINTH_AUDIT_CHECKPOINT_PATH`; keep the journal and its `.lock` file on the
same shared filesystem so the lock works across replicas.
Back up the checkpoint journal independently of the SQL dump; never replace it
with an older backup during a database restore.

`/api/admin/audit-logs/verify` reports `chain_ok` separately from
`completeness_ok`. `checkpoint_status` is `current`, `stale`, `partial_history`,
`unavailable`, `mismatch` or `invalid`. A checkpoint older than 24 hours, a
database append not yet anchored, or history predating the first checkpoint
does not establish full completeness. The response includes the checkpoint
time, epoch, count and unanchored interval. Tenant audit packets expose the
status and time without revealing the global row count. Missing checkpoints
leave internal chain validity checkable but completeness unknown. A prefix or
empty log contradicting a retained checkpoint fails verification and blocks
startup. A checkpoint write failure after a database commit leaves an
unanchored interval and surfaces an error; investigate before retrying an
operation because its audit entry may already exist.

Writers hold a cross-process lock across the database commit and journal
append. Verification reads both under the same lock, preventing concurrent
appends from causing a false truncation verdict. Keep the lock file and journal
on a shared volume when multiple application processes write one database.

For an authorized restore to an older SQL dump, preserve the journal and note
its final `seal` from the admin verification response before restoring. The
restored chain must verify internally; its mismatch with the retained head is
expected and startup remains blocked. Stop the app, restore the SQL dump, then
run the operator-only reconciliation command with the observed seal and backup
identifier:

```bash
docker compose run --rm norinth python scripts/reconcile_audit_checkpoint.py \
  --reason 'restore backups/norinth-20260915T000000Z.sql.gz' \
  --expected-seal '<final seal observed before restore>'
docker compose up -d norinth
```

Reconciliation appends a signed new epoch linked to the old one; it never
deletes old checkpoints. It marks restored history before the new epoch as
unanchored for complete-history assurance. Keep the restore authorization and
reason with the backup record. Reconciliation is deliberately absent from the
API and automatic startup path.
