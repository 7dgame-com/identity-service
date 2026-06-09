# Legacy DB Readonly Account Runbook

Phase 3 should connect to the legacy platform database with a database-level
readonly account. The application also blocks write-like SQL, but database
permissions are the final safety net.

The current develop legacy database is Tencent Cloud TDSQL-C for MySQL:

```text
MYSQL_HOST=10.206.0.14
MYSQL_DB=bujiaban_development
MYSQL_USERNAME=bujiaban
MYSQL_PASSWORD=<redacted>
```

`bujiaban` is the legacy business account. It is acceptable for temporary
comparison, but it must not be the long-running identity-service account because
it is not database-level readonly and cannot create or grant the safer account.

## Create Account

Run this with a Tencent Cloud TDSQL-C MySQL administrator account or from the
TDSQL-C console account/permission management page:

```sql
CREATE USER IF NOT EXISTS 'identity_readonly'@'%' IDENTIFIED BY '<secret>';
GRANT SELECT ON `bujiaban_development`.* TO 'identity_readonly'@'%';
FLUSH PRIVILEGES;
SHOW GRANTS FOR 'identity_readonly'@'%';
```

For another environment, replace `bujiaban_development` with the exact legacy
database name used by `LEGACY_DB_NAME`.

Develop status on 2026-06-06:

- `identity_readonly@%` has been created in the TDSQL-C console.
- `bujiaban_development` shows `identity_readonly@%` in its authorized account list.
- The `identity_service_develop` runtime Stack has been switched from the
  legacy business account to `identity_readonly`.
- Container verification passed: `SHOW GRANTS FOR CURRENT_USER()` only returned
  `USAGE` plus `SELECT` on `bujiaban_development.*`.

## Update Runtime

Update the `identity-adapter` runtime environment:

```text
LEGACY_DB_USER=identity_readonly
LEGACY_DB_PASSWORD=<secret>
```

Keep `IDENTITY_READONLY_MODE=true`.

## Verify

From the `identity-adapter` container:

```bash
node --input-type=module <<'NODE'
import mysql from 'mysql2/promise';

const connection = await mysql.createConnection({
  host: process.env.LEGACY_DB_HOST,
  port: Number(process.env.LEGACY_DB_PORT || 3306),
  user: process.env.LEGACY_DB_USER,
  password: process.env.LEGACY_DB_PASSWORD,
  database: process.env.LEGACY_DB_NAME
});

const [grants] = await connection.query('SHOW GRANTS FOR CURRENT_USER()');
console.log(JSON.stringify(grants, null, 2));
await connection.end();
NODE
```

Expected result: only `USAGE` plus `SELECT` on the target legacy database.

Then smoke test:

```bash
wget -qO- http://127.0.0.1:8086/health
wget -qO- http://127.0.0.1:8086/admin/roles
wget -qO- http://127.0.0.1:8086/admin/organizations
```

## Rollback

If the readonly account cannot read required tables, temporarily restore the
previous legacy database user in the Stack and keep `IDENTITY_READONLY_MODE=true`.
Do not proceed to phase 4 until the readonly account is working.
