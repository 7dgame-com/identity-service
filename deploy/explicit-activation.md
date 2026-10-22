# Explicit development activation

`IDENTITY_ACTIVATION_MODE=bootstrap` remains the default. It preserves the previous startup transition and does not require an activation receipt. The optional `explicit` mode separates listening from becoming authoritative. It requires `IDENTITY_DATA_SOURCE=identity`, the complete private schema, the allocator checkpoint schema, and `deploy/mysql/identity-activation-schema.sql` installed beforehand. Startup executes no schema creation, account/session issuance, event insertion, or authority update.

Deploy a fixed, reviewed image before the cutover window. Set `IDENTITY_ACTIVATION_MODE=explicit` on every candidate replica. Do not expose sealed replicas through public or internal business routes. `/health/live` returns HTTP 200 for liveness. `/health` returns HTTP 503 with `status=sealed`, `ready=false`, and the actual database authority while staging. All other controller handlers, including internal/provider/OIDC/read endpoints, return `IDENTITY_SEALED` before their authentication or business logic. HTTP parsing, CORS preflight and unmatched routes are transport behavior, not identity operations.

The final drain, sync, credential import, allocator finalization and ingress switch remain separate operator responsibilities. A sealed response is not a seamless user experience and does not prove writers have drained. This implementation does not queue users or callbacks.

## Private CLI

Use the compiled CLI in the same immutable candidate image. The revision comes from the build-generated module; an environment `IDENTITY_BUILD_REVISION` alone cannot attest it. The CLI is hard restricted to `10.206.0.5:3306`, database `xrugc_identity_dev`, authenticated principal `identity_dev`, independent data source and explicit mode. It opens no legacy database or HTTP connection, creates no principal, grants no permission, and executes no DDL.

In-process callers import `runIdentityActivateOperation(args)` from
`scripts/lib/identity-activate-operation.js`. Importing this entry or the CLI does
not execute activation. Its Promise includes the actual business operation,
prepared/intent/result report file and parent-directory fsyncs and every acquired connection/file close.
Invocation-local receipt state prevents a previous call from contaminating a later
result. It grants no admission scope or migration lease and implements no final
coordinator gate; the existing writer guard and single authority fence remain.

First inspect without changing state:

```sh
node dist/scripts/identity-activate.js --status
```

Then dry-run with the exact ready allocator manifest SHA, full candidate revision and UTC deadline. The deadline must be within five minutes according to the database clock. Use a new report path for each invocation; the CLI creates an exclusive, nonsymlink, owner-only `0600` JSONL file and fsyncs its records.

```sh
node dist/scripts/identity-activate.js \
  --expected-proof-sha256=<64-lowercase-hex> \
  --expected-revision=<40-lowercase-hex> \
  --deadline=<YYYY-MM-DDTHH:mm:ss.sssZ> \
  --report=/tmp/identity-activation-dry-run.jsonl
```

Only add `--apply` after the external writer/issuer drain and routing generation checks pass and sufficient time remains. Use a different new report file. The operation holds `identity_migration_control` through allocator verification, receipt insertion and authority update. It checks the database deadline after locking and again immediately before sending COMMIT. A validation, report-intent or deadline failure before COMMIT rolls the transaction back. Receipt and authority commit atomically; no account or credential row is written. Repeating an already completed activation with the exact same proof, compiled revision and deadline returns `already_active` without rewriting the receipt. A different activation request returns `ACTIVATION_ALREADY_ACTIVE_DIFFERENT_REQUEST`; use read-only status to inspect the existing receipt. The historical receipt revision records the initial activation and does not prevent a later reviewed image upgrade; every explicit-mode restart still validates receipt integrity, authority, the exact stored proof and current private allocator bounds.

## Uncertain outcomes

The deadline is the final permitted decision time. A client cannot guarantee when COMMIT becomes durable after the command has been sent. A lost COMMIT response returns `outcome=unknown` and exit code 3, with a durable local intent where available. The `acknowledgementAfterDeadline` flag compares the host wall clock when a successful acknowledgement is observed with the requested deadline. It does not establish the database commit time or prove that COMMIT met the deadline, and it does not imply cancellation. If COMMIT was acknowledged but writing the final report failed, the CLI reports `ACTIVATION_COMMITTED_REPORT_FAILED`, also exit code 3.

Any connection/file close failure is also explicit and conservative:
`MIGRATION_RESOURCE_CLOSE_UNKNOWN`, exit 3, `statusRequired=true`. Even an
acknowledged activation is not reported as completed until every close settles.
Errors from the business operation, failure-report write and resource cleanup are
preserved in the rejected Promise's cause chain; CLI output remains count/code-only.

A prepared or commit-intent report write/fsync failure also rejects with
`MIGRATION_REPORT_WRITE_UNKNOWN`, exit 3 and `statusRequired=true`. Report failures
remain latched if later rollback or failure-report errors replace the original
exception. This conservative result grants no automatic retry, even when the
failure happened before the core operation could send COMMIT.

In all these cases, keep old identity writers stopped and routing gated. Run the read-only `--status` from the fixed image and compare receipt proof/request/revision with the protected intent. An active receipt confirms authority; staging with no receipt means that activation did not persist. A failed or inconsistent status requires investigation. Never infer rollback from a timeout, destroy the receipt, downgrade authority, retry COMMIT automatically or resume legacy writers. There is no public activation endpoint and no additional activation credential.

An existing `bootstrap` deployment already authoritative without a receipt cannot be switched to explicit mode by silently inventing a historical receipt. That case requires its own reviewed transition. Preparing an empty receipt table is not activation.
