# Preserve in-flight PHP email/password challenges

This offline tool migrates the final drained Redis snapshot into the private Identity database. It does not connect to Redis, issue new credentials, deliver mail, change passwords, or extend any deadline. Default execution is dry-run; apply additionally requires `NODE_ENV=staging` and the persistent migration control row to remain `staging`. Once native authority is activated, changing environment variables cannot reopen import.

Apply `identity-legacy-challenge-schema.sql` and `identity-password-reset-token-schema.sql` to the **private** database before rehearsal. The first schema also preserves millisecond issuance precision for email-change tokens. Standalone fresh initialization includes both; existing installations must run these schema upgrades explicitly before the import transaction.

## Evidence and compatibility baseline

The audited PHP issuers use these exact keys and independent TTLs:

| Key                                         | Value                                   | Original TTL |
| ------------------------------------------- | --------------------------------------- | ------------ |
| `password:reset:code:<normalized-email>`    | JSON `code,email,user_id,created_at`    | 900 s        |
| `password:reset:<32-character-token>`       | JSON `email,user_id,created_at`         | 1800 s       |
| `password:reset:attempts:<email>`           | integer count, expiry set on first miss | 900 s        |
| `email:ratelimit:request_reset:<email>`     | integer count                           | 60 s         |
| `email:verify:<normalized-email>`           | JSON **only** `code,created_at`         | 900 s        |
| `email:verify:attempts:<email>`             | integer count, expiry set on first miss | 900 s        |
| `email:ratelimit:send_verification:<email>` | integer count                           | 60 s         |
| `email:change:token:<integer-user-id>`      | 48-character random token               | 600 s        |

Old email verification codes prove control of an email globally and contain no requesting user ID. Identity consumes an email challenge for an explicit authenticated user. The importer therefore requires either an exact baseline association or a documented, reviewed association. It **never** guesses the requesting user from the destination email. A code for a new email may belong to a user whose current account email is different or absent; the supplied current-account email must match the private account snapshot.

Before cutover, deploy the compatibility baseline and enable `IDENTITY_CAPTURE_LEGACY_EMAIL_CHALLENGES=true` on **every** old email-code issuer. Its Redis 7 companion key is `identity:legacy_email_challenge:<SHA256(normalized-target-email)>`, with JSON:

```json
{
  "issuer": "yii-email-code-v1",
  "user_id": 24,
  "account_email": "old@example.com",
  "target_email": "new@example.com",
  "code_hash": "<SHA256 of the exact old six-digit code>",
  "issued_at": 1700000000,
  "expires_at_ms": 1700000900123
}
```

`account_email` may be `null` for proven initial email binding. The companion preserves the old code's exact Redis deadline; it does not change the old payload or response. The importer verifies target digest, code digest, original issued time, exact expiration, user ID, and current private account email. Metadata from a different code/issuer/account or an orphan companion is rejected.

Wait **at least the original 900-second maximum email-code TTL after all issuers run the baseline** before the final drain. Anonymous or otherwise unprovable issuers still require reviewed associations. If all still-active codes cannot be completely and correctly associated within the cutover budget, **cancel the cutover**. Do not silently omit a credential, invent an association, or make users request another code. The separate QR baseline has its own longer waiting period and remains a prerequisite.

## Final snapshot

Drain all old challenge send/verify/consume/reset writers, including code overwrites, mail-delivery cleanup, attempts increments, and email-change consumption. Do not import an intermediate live snapshot: a code consumed or replaced after export could otherwise be imported as active. Keep ordinary unrelated business requests available. Abort the switch if drain/export/import exceeds the agreed request budget.

A trusted, read-only exporter must collect `GET`, Redis server `TIME`, `PTTL`, and **`PEXPIRETIME` together atomically for each key**, after draining writers. Store the exact absolute deadline as `expires_at_ms`; the tool cross-checks TIME/PTTL but never calculates the authoritative deadline from a local clock. Redis versions lacking `PEXPIRETIME`, missing keys, non-expiring keys, or unknown original expiry evidence are not eligible for automatic migration. No exporter in this task accesses a running business Redis.

Write a permission-0600 offline JSON manifest without command-line credentials or logging values:

```json
{
  "version": 1,
  "final_drained_snapshot": true,
  "records": [
    {
      "key": "password:reset:code:old@example.com",
      "value": "{\"code\":\"123456\",\"email\":\"old@example.com\",\"user_id\":24,\"created_at\":1700000000}",
      "redis_time_ms": 1700000100123,
      "pttl_ms": 800000,
      "expires_at_ms": 1700000900123
    }
  ],
  "reviewed_email_associations": []
}
```

Include all active attempt/rate keys even when the corresponding code is absent. Include valid companion records in the same `records` array. Where baseline evidence is unavailable, `reviewed_email_associations` accepts `{ "email": "target@example.com", "user_id": 24, "account_email": "old@example.com", "review_reference": "reviewed-request-evidence-24" }`. An email-change token requires a reviewed current-account association whose `email` equals `account_email`; its key provides the integer user ID. Its issuer stores no creation timestamp, so the importer recovers issuance as its **proven original SETEX deadline minus the audited fixed 600 seconds**, never from remaining TTL or the import time.

Reset code/token account ID and email come from their original payload and must match a current active, non-deleted, verified private account. Email-code reviews must match the current active account email. Configure the **same native salts used by the deployed Identity service** (`IDENTITY_PASSWORD_RESET_CODE_HASH_SALT`, `IDENTITY_EMAIL_CODE_HASH_SALT`) before dry-run and apply. Codes and change tokens are stored only as the native salted hashes. Opaque 32-character reset tokens are stored only as SHA-256 digests in `identity_password_reset_tokens`; a code challenge key is never a reset bearer.

```sh
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity pnpm exec tsx scripts/legacy-challenge-import.ts --file=/secure/offline/final-challenges.json --dry-run
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity pnpm exec tsx scripts/legacy-challenge-import.ts --file=/secure/offline/final-challenges.json --apply
```

The CLI uses only `IDENTITY_DB_*`, logs aggregate counts, accepts at most 100,000 records and a 64 MiB file, and never prints SQL, raw keys, codes, or tokens. Import is one transaction under the durable staging lock. Expired credentials retain their original expired deadline; they are never renewed. A credential-free source-key/payload ledger makes replay idempotent without resetting consumed state or attempts. Changed final snapshots and source attempts to replace a newer native challenge fail closed. A fresh snapshot after a cancelled rehearsal requires a freshly prepared staging target, not overwriting an earlier challenge snapshot.

Native repositories continue reading imported independent rate/attempt windows. A new code does not erase the original lock; failures increment the same original attempt window atomically without extending it. An imported code's creation time is not used to guess its send cooldown. Keep the companion schema and ledger after cutover. Application rollback continues using Identity as the authority and does not re-enable these old writers or restore old credentials.

Disposable MySQL coverage: `apps/identity-adapter/test/legacy-challenge-import.mysql.spec.ts`, including original-code/token usability, exact deadlines, reviewed and baseline association proof, independent lock/rate preservation after resending, concurrent idempotency, expired/consumed replay, all-or-nothing rollback, and the permanent authority fence. No production Redis or account data is used.
