# Staging account delta synchronization

`scripts/account-sync.ts` advances a **one-way staging baseline** established by
`scripts/account-import.ts`. It does not enable dual writers. The source connection
uses a read-only, repeatable-read consistent snapshot; its database user should have
only `SELECT` privileges on the legacy identity tables. Private database credentials
must never be the legacy database credentials.

Build the service, configure the explicit `LEGACY_DB_*` and `IDENTITY_DB_*` endpoints,
then preview the bounded delta:

```sh
node dist/scripts/account-sync.js --dry-run --max-changes=500 --max-rows=100000
```

`--report=/protected/new-sync.json` additionally writes the complete report to a new
owner-only 0600 regular file and waits for `writeFile`, file `fsync`, parent
directory `fsync` and every descriptor close.
The destination is never overwritten or followed through a symlink. In-process
callers import `runAccountSyncOperation(args)` from
`scripts/lib/account-sync-operation.js`; importing it or the compatibility CLI
does not execute a migration. Its Promise settles only after the business Promise
and every acquired connection/file close have settled. A failed close rejects with
`MIGRATION_RESOURCE_CLOSE_UNKNOWN`; a report write/fsync failure rejects with
`MIGRATION_REPORT_WRITE_UNKNOWN`. The CLI exits 3, emits no success and forbids
automatic retry for either outcome, including a failure after a committed sync.
Check current database state before any separately reviewed retry.

The MySQL resource owner listens from each connection's acquisition, including
while the second endpoint is connecting, and waits for both `end()` and the actual
socket `close` event. mysql2's `end()` fulfillment alone is not closure proof.
Connection/transport errors and a fulfilled `Error` result remain unknown. A
report durability failure is latched even if a later rollback error replaces the
original exception. Report content or file existence alone never proves that all
connections and descriptors have closed.

This awaited entry does not create an admission scope, acquire a migration lease,
enforce the coordinator's finalization ledger or grant authorization. The existing
writer guard still refuses it when admission is enabled without a reviewed scope.

Review the count-only report. To apply a rehearsed staging delta:

```sh
node dist/scripts/account-sync.js --apply --max-changes=500 --max-rows=100000
```

Omitting `--apply` is a dry run; `--dry-run` wins when both flags are supplied.
`--max-changes` is mandatory and bounds both changed account rows and affected
subject outbox events. Global role/policy changes can affect every subject even when
only one policy row changed. `--max-rows` bounds each source and target table, rather
than truncating the comparison. Exceeding either budget aborts the whole batch.
Row counts are a work bound, **not a request-latency guarantee**: the final cutover
controller must also enforce its elapsed-time budget and cancel before persisted
authority activation when the database or network exceeds it. After activation,
recover applications against Identity instead of reopening the legacy writer.

The target transaction locks `identity_migration_control` before starting the source
snapshot, checks every current target row against the full-import baseline, then
commits data, the next baseline and ordered subject events together. Any missing or
unknown target row, changed target hash, changed source schema, or failed SQL aborts
the entire batch. It does not silently adopt or overwrite private database changes.
Retried committed batches have zero changes. The importer includes identity profile
avatar references but excludes business balances and file records.

Deleted source users remain private-database tombstones with their original integer
IDs and disabled subject mappings; their sessions are revoked. Deleted relations
remain recorded as null source/target hashes in the baseline. The source cannot
reuse a tombstoned integer ID. Tombstones retain the existing unique account names
and addresses; any source reuse that conflicts with them requires explicit review
and fails the batch rather than replacing another identity.

During rehearsal, run dry-run and staging sync repeatedly while legacy remains the
sole writer. For the final handoff, drain legacy account writes first, take the final
account delta and final session manifests, apply them while authority is still
`staging`, and complete the checked routing change. A consistent snapshot alone does
not stop later legacy writes. Session manifests must be the final drained snapshot;
session import does not remove consumed legacy refresh tokens from earlier exports.

Native Identity bootstrap permanently changes the persisted authority to `identity`.
After that, account synchronization and session import apply must refuse legacy
data even when environment variables are switched back. A completed full account
import may return its existing count-only replay result without writing any data;
new full imports remain forbidden. Roll
back applications against the Identity authority; do not restore legacy as a second
identity writer or manually reset the authority row. A reverse data migration needs
its own reviewed procedure.

Errors and reports omit source row values, passwords, refresh tokens and SQL. Keep
database and application logging configured to avoid credential-bearing SQL.
