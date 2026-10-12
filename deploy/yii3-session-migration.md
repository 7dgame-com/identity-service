# Yii3 login and session cutover

This preserves the existing y1 login-code/refresh contract while Identity owns
accounts and sessions. It does not read Redis at runtime. Both internal POST
routes require `x-identity-internal-token` equal to
`IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN` (the existing auth scoped key).
The configured key must contain at least 32 bytes.
An IAM scoped key alone must not authorize them.

* `/internal/yii3/login-code`: `{key, operation:"context"|"redeem"}`. Context
  returns only `{frontendDomain}`. Redeem returns `{authTokens, subject,
  frontendDomain}` and creates a distinct session for each device inside the
  original 60-second window. It does not consume or extend the code.
* `/internal/yii3/refresh`: `{refreshToken, allowLoginCode:boolean}`. y1 v1
  supplies true for historical bare/wrapped codes; v2 supplies false. A stored
  refresh, including a revoked/expired predecessor, always stays a refresh.
  Failed refreshes never fall back to code redemption. Unknown `dsn_` tokens
  cannot become ordinary login codes.

`authTokens` is the existing flat Identity `response.token` object, including
`accessToken`, `refreshToken` and UTC ISO `expires`. PHP converts the expiry to
its historical Asia/Shanghai display. Current private account status, roles,
revocation and SN provenance are checked before returning the subject. Verified
SN subjects include `auth_method`/`device_sn_id` together at the top level.
`frontendDomain` is display/redirect metadata only; it never selects JWT audience.
New code issuance stores a host only when the browser's Origin (or, when Origin
is absent/blank, Referer) exactly matches a canonical
`IDENTITY_CORS_ORIGINS` entry. Keep that list aligned with PHP's reviewed
`CORS_ALLOWED_ORIGINS`; the PHP gateway forwards only the original Origin and
Referer for this purpose. An explicit untrusted Origin never falls back to a
trusted Referer. HTTP origins are restricted to localhost/loopback hosts.

## Offline old refresh export

The operator must independently review the running y1 code revision and all
writers of Redis DB1's exact `refresh_token:` namespace. The reviewed writer
must use `SETEX 2592000` only when creating a random refresh token and never
renew that token's TTL. Without this evidence, expiry minus 30 days cannot be
used as an issuance time and this export must stop. The snapshot's reviewed
fields record that evidence; they do not prove that writers have stopped.

Capture into a new mode-0600 regular JSON file, without printing raw tokens,
Redis values or key material. The snapshot contract is:

```json
{
  "version": 1,
  "source": {
    "application": "yii3-a1",
    "sourceRevision": "0000000000000000000000000000000000000000",
    "redisDatabase": 1,
    "keyPrefix": "refresh_token:",
    "fixedTtlSeconds": 2592000,
    "expiryPolicy": "setex-on-create-only",
    "namespaceWritersReviewed": true
  },
  "capturedAtMs": 1800000000000,
  "entries": [{
    "key": "refresh_token:<raw-64-lowercase-hex-or-dsn_plus_64-hex>",
    "value": "42",
    "expiry": {
      "kind": "pexpiretime",
      "expiresAtMs": 1800000100123,
      "observedAtMs": 1800000000000
    }
  }]
}
```

All revision/time/credential values above are placeholders, not evidence. An
ordinary token's value must be its original scalar positive integer string.
An SN token must be `dsn_` followed by 64 lowercase hex characters and its value
must be the exact JSON object (or its original JSON string):
`{version:1,user_id:42,auth_method:"device_sn",device_sn_id:9}`. Missing/extra
source fields, mixed formats and duplicate keys are rejected.

If Redis supports `PEXPIRETIME`, preserve its full absolute millisecond value.
Otherwise record an ordered, same-Redis-clock observation:

```json
{"kind":"time-pttl-bracket","timeBeforeMs":1800000000000,"pttlMs":100123,"timeAfterMs":1800000000010}
```

Read `TIME` before the bounded value/PTTL observation and `TIME` afterward.
The gap must be at most 2000 ms, and the final snapshot capture must follow the
observation by at most 60000 ms. Expiry uses `timeBeforeMs + pttlMs`, the
conservative lower bound: it may shorten a few milliseconds, never extend TTL.
The derived issuance time uses that same bound minus the reviewed fixed TTL.
Deleted, persistent, replaced or otherwise inconsistent observations must be
recaptured or rejected, not filled in from application time.

After compiling, the exporter requires no database or Redis connection:

```bash
node dist/scripts/yii3-session-export.js \
  --snapshot=/protected/yii3-refresh-snapshot.json \
  --out=/protected/new-yii3-session-manifest.json
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity \
  node dist/scripts/legacy-session-import.js \
  --file=/protected/new-yii3-session-manifest.json --dry-run
```

The new manifest contains only SHA256 refresh digests, deterministic family
IDs, original lifetimes, actor IDs and source evidence. Its report prints
counts only and always says `notFinal:true`, `sourceWrites:0`, `targetWrites:0`.
Neither an operator declaration nor a successful rehearsal establishes a final
drain. Active SN imports additionally require the configured independent
`DEVICE_SN_DB_*` source and live private account/role eligibility; unavailable,
disabled, moved or elevated device accounts fail closed. Dry-run performs the
same check. Expired historical SN rows remain unusable without extending them.

Use scratch copies for rehearsal only. The final target remains the existing
Identity private database, retaining its ongoing legacy Identity session
rotations/revocations. Never restore an early scratch copy over that database.
For final application: stop all old y1 refresh writers, verify that drain by
independent runtime/traffic evidence, capture again, dry-run, then explicitly
repeat the import command with `--apply` while private authority is still
`staging`. This importer is insert-only and preserves every existing lifetime,
revocation and successor. It does not reconcile missing rows from stale
snapshots. Therefore do not pre-import y1 sessions into the final target while
the old writer is live. Audit actual old Identity session changes separately.
The persistent authority fence rejects imports after native bootstrap activates
Identity. Do not start native HTTP merely to test the offline tooling.

## Old access-token trust

The old y1 `JwtService` uses HS256, `uid` and fractional PHP `iat`/`exp`, with an
access lifetime of at most 10800 seconds. It has no issuer/audience/typ claims.
This trust is separate from Yii2 ES256 and auth-service OAuth compatibility.
It stays disabled unless `IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE` points to a
reviewed JSON file, for example:

```json
{"version":1,"algorithm":"HS256","secretFile":"/run/secrets/old-yii3-jwt-key","issuedBefore":"2000-01-01T00:00:00Z","acceptUntil":"2000-01-01T03:00:00Z","maxAccessTtlSeconds":10800}
```

The example is deliberately expired. Set cutover deadlines from real final
writer evidence and mount the existing PHP key read-only; never print it,
generate a replacement and call it old, or reuse the auth-service trust key.
PHP `trim()` byte semantics are preserved. Config/key removal takes effect on
the next verification. Only the original claims and paired SN fields are
accepted; OAuth/native/session claims, another algorithm, a wrong signature,
late issue or expiry fail closed. Every acceptance still checks the private
account's current state and revocation cutoff and the independent SN source.
Old access tokens have no session ID: family logout cannot retroactively add
one. They retain the original bounded access lifetime, while password/global
account revocation applies immediately. Remove this trust after the reviewed
compatibility window.
