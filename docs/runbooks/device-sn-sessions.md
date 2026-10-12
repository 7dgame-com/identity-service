# Device SN sessions

SN activation and UUID binding remain in the main backend. The trusted internal
`POST /internal/auth/issue-user-token` accepts `legacyUserId` plus the paired fields
`auth_method: "device_sn"`, `device_sn_id: <positive integer>`. The existing internal
service credential is required. Public login/refresh cannot choose a session source.
Responses retain the standard token object (`token`, `accessToken`, `refreshToken`,
`expires`, `tokenType`). SN access tokens expire within 10,800 seconds.

Before enabling this flow:

1. Apply the main backend `device_sn` migration, then apply
   `deploy/mysql/migrations/20260926_device_sn_sessions.sql` to the existing identity
   database. It is safe to rerun. Fresh installations use `deploy/mysql/init.sql`.
   The session repository also upgrades the two nullable columns when its existing
   schema initialization runs; migration errors fail the operation closed.
2. Point `LEGACY_DB_*` at the same authoritative writer used by both main backends
   for SN/account state. An asynchronous read replica or independent database
   cannot enforce this contract. The identity reader needs SELECT on `device_sn`,
   `user`, and `auth_assignment`; it does not write to those tables. UUID bindings
   live directly in nullable, unique `device_sn.device_uuid`; the legacy `device`
   table is not read, written or required by this flow.
3. Call `GET /internal/auth/device-sn/readiness` with `X-Identity-Internal-Token`.
   Require `ready`, `sessionSchema`, and `legacySchema` all true. This endpoint only
   inspects schemas; it neither runs a migration nor proves deployment topology.
4. Verify A activation → B login/refresh, A disable → B login/refresh rejection,
   and role elevation → old SN access rejection. Verify matching JWT keys/issuer
   and the <=3h lifetime against the main API.

Each device issue/refresh reads current SN, its valid `device_uuid`, activation
timestamp and account eligibility from the authoritative legacy DB. First activation
binds the UUID in the main backend; disabling SN preserves that binding. Stored UUIDs
must match the complete lowercase ASCII pattern `[a-z0-9][a-z0-9._:-]{0,254}`;
missing, empty, malformed or partially bound records cannot authorize a session.
The pair of provenance fields is stored with each identity refresh session,
copied on rotation and emitted as JWT
`auth_method`/`device_sn_id`. Missing halves and unsupported source types are rejected.
Concurrent refreshes use a row lock so only one replacement can be issued.
Ordinary historical sessions retain NULL sources and their existing behavior.

Existing SN access tokens may finish their lifetime after SN disable. Account
deletion, disabled account status or assignment of root/admin/manager rejects SN
access immediately. SN sessions cannot mint OIDC authorization codes or refresh
through OIDC, nor mutate password/email credentials through the identity API.
These checks apply before legacy-proxy account calls as well as native handlers.
Main-backend QR code issuance must apply the corresponding source restriction.

The main backend must not fall back to ordinary legacy issuance on **any** device
identity failure, including authorization rejection, missing schema, timeout and
signing failure. Sources never contain raw SN or UUID values. The Rokid client
keeps its chosen UUID+SN automatic login behavior; standard refresh remains
compatible and continues to enforce the current SN authorization.

## Apply the incremental identity migration

Run this **inside the newly deployed identity-adapter container**, whose existing
`IDENTITY_DB_*` environment selects the intended identity database. The SQL is
included in the runtime image. Apply the main API's `device_sn` migration first.
Do not run the full `init.sql` against an existing installation.

```sh
node --input-type=module <<'NODE'
import mysql from 'mysql2/promise';
import { readFile } from 'node:fs/promises';
for (const key of ['IDENTITY_DB_HOST', 'IDENTITY_DB_NAME', 'IDENTITY_DB_USER']) {
  if (!process.env[key]) throw new Error(`Missing ${key}`);
}
const db = await mysql.createConnection({
  host: process.env.IDENTITY_DB_HOST,
  port: Number(process.env.IDENTITY_DB_PORT || 3306),
  database: process.env.IDENTITY_DB_NAME,
  user: process.env.IDENTITY_DB_USER,
  password: process.env.IDENTITY_DB_PASSWORD || '',
  multipleStatements: true
});
try {
  await db.query(await readFile('/app/deploy/mysql/migrations/20260926_device_sn_sessions.sql', 'utf8'));
  const [columns] = await db.query(`SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE
    FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'identity_refresh_sessions'
      AND COLUMN_NAME IN ('auth_method', 'device_sn_id') ORDER BY COLUMN_NAME`);
  if (columns.length !== 2 || columns.some(column => column.IS_NULLABLE !== 'YES')) {
    throw new Error('Device SN session schema verification failed');
  }
  console.log(JSON.stringify({ migration: '20260926_device_sn_sessions', columns }));
} finally { await db.end(); }
NODE
```

This adds nullable `auth_method VARCHAR(32)` and `device_sn_id INT` only; existing
session rows remain valid ordinary sessions. Reruns retain all rows and do not
alter either source column once present. Apply it to every distinct identity
database used by the deployment. Nodes sharing one database need one application.

## Verify the running node

Run this in **each running identity-adapter container** after confirming its image
digest/build revision matches the release. It uses the existing internal token
without printing that credential or changing the configured auth provider.

```sh
node --input-type=module <<'NODE'
const token = process.env.IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN ||
  process.env.IDENTITY_ACCOUNT_INTERNAL_TOKEN || process.env.IDENTITY_INTERNAL_API_TOKEN;
if (!token) throw new Error('Internal identity token is not configured');
const response = await fetch(`http://127.0.0.1:${process.env.PORT || 8086}/internal/auth/device-sn/readiness`, {
  headers: { 'X-Identity-Internal-Token': token }, signal: AbortSignal.timeout(10000)
});
const result = await response.json();
console.log(JSON.stringify({ status: response.status, ...result }));
if (!response.ok || result.ready !== true || result.sessionSchema !== true || result.legacySchema !== true) {
  process.exitCode = 1;
}
NODE
```

Expected result is HTTP 200 with all three readiness fields `true`. A healthy
`/health` alone is insufficient. Readiness verifies columns and read access, but
not shared authoritative data, JWT keys or cross-backend behavior; complete the
functional checks above before accepting the deployment.

## Develop CI gates

The existing pipeline installs the lockfile with `npm ci`, then runs **plain
`npm audit`** (all severities, including development dependencies), the full
test suite, TypeScript build, compiled-revision validation and Compose validation.
Develop pushes additionally generate and retain the organization regression
evidence. The MySQL job now also runs `device-sn-sessions.mysql.spec.ts` against
its disposable MySQL 8.4 service; these tests do not create a legacy `device`
table. Both test jobs must pass before the image build/push. Do not weaken the
audit gate or switch `AUTH_PROVIDER` to bypass a failure.
