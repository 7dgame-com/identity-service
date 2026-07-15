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
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_ENABLED=false
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_MAX_BATCH=50
IDENTITY_IAM_PROFILE_WRITE_MODE=disabled
IDENTITY_IAM_ROLE_WRITE_MODE=disabled
IDENTITY_IAM_ORG_WRITE_MODE=disabled
IDENTITY_IAM_PLUGIN_USER_WRITE_MODE=disabled
IDENTITY_USAGE_BILLING_DRY_RUN=true
```

Only set `IDENTITY_IAM_RECONCILIATION_ENABLED=true` for a bounded shadow apply
window. Set it back to `false` immediately after the apply batch. The dedicated
role/organization materialization control is also default-off and must never be
enabled as part of a generic reconciliation command.

## Public Checks

The internal IAM endpoints should not be routed through public Traefik labels.
From outside the container, `/internal/iam/reconciliation/status` should return
404 or be unreachable.

```sh
curl -sS https://identity.d.xrteeth.com/health
curl -sS https://identity.d.tmrpp.com/health
curl -sS -o /dev/null -w '%{http_code}\n' https://identity.d.xrteeth.com/internal/iam/reconciliation/status
```

## tmrpp Deployment Note

Do not use `tmrpp` Portainer for stage 7 acceptance. The `tmrpp` side is
deployed through the elastic server image workflow. Validate it with public
health checks and with command output copied from the target container or host
shell.

The minimum public checks are:

```sh
curl -sS https://identity.d.tmrpp.com/health
curl -sS https://identity.tmrpp.com/health
curl -sS -o /dev/null -w '%{http_code}\n' https://identity.d.tmrpp.com/internal/iam/reconciliation/status
curl -sS -o /dev/null -w '%{http_code}\n' https://identity.tmrpp.com/internal/iam/reconciliation/status
```

The internal smoke/dry-run/gate checks below still need to run inside the
`identity-adapter` container, either directly from the container shell or
through a host-side `docker exec`.

If running from the host shell, first find the adapter container:

```sh
docker ps --format '{{.Names}}' | grep 'identity-adapter'
```

Then replace `<adapter-container>` and run these read-only checks:

```sh
docker exec <adapter-container> /bin/sh -lc \
  'node dist/scripts/iam-reconciliation-smoke.js >/tmp/stage7-smoke.log 2>&1; echo STAGE7_SMOKE_EXIT:$?; grep -E "^\[(health|readiness|reconciliation\.status\.(before|after))\]" /tmp/stage7-smoke.log'

docker exec <adapter-container> /bin/sh -lc \
  'node dist/scripts/iam-reconciliation-smoke.js --dry-run --legacy-user-id=25 --run-key=stage7-tmrpp-dev-dry-run-25 >/tmp/stage7-dryrun.log 2>&1; echo STAGE7_DRYRUN_EXIT:$?; grep -E "\"dryRun\"|\"applyShadow\"|\"shadowWriteCount\"|\"passed\"|\"blockers\"|P0|P1" /tmp/stage7-dryrun.log | tail -n 40'

docker exec <adapter-container> /bin/sh -lc \
  'node dist/scripts/iam-reconciliation-smoke.js --require-gate >/tmp/stage7-gate.log 2>&1; echo STAGE7_GATE_EXIT:$?; grep -E "\"passed\"|\"blockers\"|lastSucceededRun|runKey|P0|P1|canCutoverIdentityPrimary" /tmp/stage7-gate.log | tail -n 40'
```

Expected:

- all three exit markers are `0`
- dry-run shows `dryRun:true`, `applyShadow:false` and `shadowWriteCount:0`
- gate shows `passed:true`, `blockers:[]` and `canCutoverIdentityPrimary:false`

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

## Role and Organization Shadow Materialization

Use this path only to repair role/organization shadow baseline P1 findings
while profile and plugin-user can continue on their independently approved
`legacy-proxy` tracks. It writes only the Identity shadow/read-model rows, the
base legacy subject mapping required for that shadow, and the reconciliation
ledger. It never writes legacy RBAC tables, changes authorization responses, or
enables any IAM write mode.

This path is intentionally separate from the global reconciliation safety gate:
that gate can remain unable to apply while unrelated profile/plugin write tracks
are not `disabled`. Do not disable those tracks merely to make the global gate
green. Instead, require the scoped readiness block
`rolePermissionMaterialization.canApply=true` with no blockers.

### Small Apply Sample

Before this step, use a separately approved Develop-only window and temporarily
set exactly:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=true
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_ENABLED=true
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_MAX_BATCH=50
IDENTITY_IAM_MODE=readonly
IDENTITY_IAM_ROLE_WRITE_MODE=disabled
IDENTITY_IAM_ORG_WRITE_MODE=disabled
```

Confirm the scoped readiness before applying. The global
`safetyGate.canApplyShadow` may still be `false` and is not the criterion for
this materialization path.

Then run only the allowed scopes, starting with one known safe test account:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --apply-shadow \
  --confirm-apply-shadow \
  --legacy-user-id=25 \
  --scopes=role,organization \
  --limit=1 \
  --run-key=iam-role-org-materialization-dev-25
```

Immediately after the batch, restore:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=false
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_ENABLED=false
```

Then rerun a scoped dry-run:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --dry-run \
  --legacy-user-id=25 \
  --scopes=role,organization \
  --limit=1 \
  --run-key=iam-role-org-materialization-dev-25-after
```

Expected: no P0/P1 results for the materialized scopes, and no unexpected
profile/plugin write evidence. Stop immediately on any P0/P1 result, an
unexpected scope, or a failed restore.

## Cursor Expansion

After the small sample passes and has a separately approved expansion window,
expand only role/organization with bounded cursor batches:

```sh
node dist/scripts/iam-reconciliation-smoke.js \
  --apply-shadow \
  --confirm-apply-shadow \
  --after=0 \
  --limit=50 \
  --scopes=role,organization \
  --run-key=iam-role-org-materialization-dev-after-0-limit-50
```

Use `data.batch.nextAfterLegacyUserId` from the run output as the next `--after`
value. Never raise the materialization batch cap above `50` in this path.

## Rollback

Rollback is configuration-only:

```env
IDENTITY_IAM_RECONCILIATION_ENABLED=false
IDENTITY_IAM_ROLE_PERMISSION_MATERIALIZATION_ENABLED=false
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
