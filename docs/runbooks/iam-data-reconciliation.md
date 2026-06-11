# IAM Data Reconciliation Runbook

This runbook covers stage 7 only. Stage 7 prepares IAM data migration through
readonly checks, shadow reconciliation and P0/P1 gates. It does not switch
`IDENTITY_IAM_MODE=identity-primary`, does not enable IAM write modes and does
not charge from usage billing shadow data.

## Safety Defaults

Keep these flags in develop and production unless a step explicitly says
otherwise:

```env
IDENTITY_IAM_ENABLED=true
IDENTITY_IAM_MODE=readonly
IDENTITY_IAM_AUTO_ENSURE_SCHEMA=true
IDENTITY_IAM_RECONCILIATION_ENABLED=false
IDENTITY_IAM_PROFILE_WRITE_MODE=disabled
IDENTITY_IAM_ROLE_WRITE_MODE=disabled
IDENTITY_IAM_ORG_WRITE_MODE=disabled
IDENTITY_IAM_PLUGIN_USER_WRITE_MODE=disabled
IDENTITY_USAGE_BILLING_DRY_RUN=true
```

Only set `IDENTITY_IAM_RECONCILIATION_ENABLED=true` for a bounded shadow apply
window. Set it back to `false` immediately after the apply batch.

## Public Checks

The internal IAM endpoints should not be routed through public Traefik labels.
From outside the container, `/internal/iam/reconciliation/status` should return
404 or be unreachable.

```sh
curl -sS https://identity.d.xrteeth.com/health
curl -sS https://identity.d.tmrpp.com/health
curl -sS -o /dev/null -w '%{http_code}\n' https://identity.d.xrteeth.com/internal/iam/reconciliation/status
```

## Container Checks

Run these inside the `identity-adapter` container. The runtime image contains
the compiled smoke script under `dist/scripts`.

```sh
node dist/scripts/iam-reconciliation-smoke.js
```

This checks:

- `/health`
- `/internal/iam/readiness`
- `/internal/iam/reconciliation/status`

It does not write data.

## Dry-Run Small Sample

Dry-run is safe while `IDENTITY_IAM_RECONCILIATION_ENABLED=false`.

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --dry-run \
  --legacy-user-id=25 \
  --run-key=stage7-dev-dry-run-25
```

Expected:

- request succeeds
- `dryRun=true`
- `shadowWriteCount=0`
- P0/P1 mismatches are either zero or recorded for repair

## Shadow Apply Small Sample

Before this step, temporarily set:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=true
```

Then run:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --apply-shadow \
  --confirm-apply-shadow \
  --legacy-user-id=25 \
  --run-key=stage7-dev-apply-25
```

Immediately after the batch, restore:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=false
```

Then rerun dry-run:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --dry-run \
  --legacy-user-id=25 \
  --run-key=stage7-dev-dry-run-25-after-apply \
  --require-gate
```

If `--require-gate` fails, do not expand the batch.

## Cursor Expansion

After the small sample passes, expand with cursor batches:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --dry-run \
  --after=0 \
  --limit=100 \
  --run-key=stage7-dev-dry-run-after-0-limit-100
```

Use `data.batch.nextAfterLegacyUserId` from the run output as the next `--after`
value. Apply shadow only for a bounded batch and only while reconciliation is
temporarily enabled.

## Rollback

Rollback is configuration-only:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=false
IDENTITY_IAM_MODE=readonly
IDENTITY_IAM_PROFILE_WRITE_MODE=disabled
IDENTITY_IAM_ROLE_WRITE_MODE=disabled
IDENTITY_IAM_ORG_WRITE_MODE=disabled
IDENTITY_IAM_PLUGIN_USER_WRITE_MODE=disabled
```

Do not delete `identity_*_shadow` or `iam_reconciliation_*` rows during rollback.
They are non-user-facing audit/shadow data and can be rebuilt.

## Remediation

| Problem | Action |
|---|---|
| Schema table is missing | Run `/internal/iam/schema/ensure`, restart if needed, rerun readiness. |
| P0 mismatch | Stop expansion and fix mapping before any future cutover. |
| P1 mismatch | Fix or create an auditable exemption before expanding. |
| Mismatch count expands unexpectedly | Stop new runs, keep run records, compare with previous batch. |
| Dual-domain mismatch | Pause load balancing or pin healthy side, align DB/Redis/Keycloak/flags. |
| Internal endpoint is public | Remove Traefik routing for `/internal/*` immediately. |
