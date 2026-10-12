# Yii2 Redis ActiveRecord refresh credential migration

This feature supersedes the 907bda56 baseline only for reviewed Yii2 Redis AR credentials. The y1 `refresh_token:<64hex>` / `dsn_<64hex>` SETEX migration remains a separate path. No live Redis capture or final snapshot has been validated by this implementation. The local MySQL and HTTP tests use disposable fixtures only.

A1 source `f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74` uses `RefreshToken` attributes `id,user_id,key`, a default 32-character random plaintext key, and exact plaintext lookup. Yii Redis AR writes `refresh_token:a:<id>` hashes without Redis expiry. It provides no trustworthy creation time or expiry. Do not manufacture an issuance time or a 30-day TTL.

The current shared dev DB1 read-only inventory found 26 AR hashes with `created_at/expires_at` and `PTTL=-1`; none has only three fields. A further aggregate found all 26 original expiries already passed, with 64-hex keys whose encoding remains unproven and no marked revocation. These observations do not establish per-record encoding, account ownership or A1 compatibility, and must not promote those expired records to valid credentials. The same namespace also contains three y1 strings; they must not enter this importer. A1 can still issue new plaintext records before its writers drain, so the final reviewed snapshot is still required.

The server consumer checks its record expiry. The legacy A1 consumer ignores that field and looks up the exact plaintext key. Therefore every original `expires_at` stays in the manifest and ledger. Only a record explicitly marked `a1Compatible:true`, with `keyEncoding:"plain"` and reviewed exact A1 lookup evidence (`source.a1LookupReviewed:true`), can use the A1 exception through the authenticated internal route. This exception can accept a record whose original expiry has passed; generic/public refresh still rejects it. Public/server exchange separately requires `serverCompatible:true`, `source.serverLookupReviewed:true` and a reviewed `serverRevision`. An A1-only permanent credential does not acquire generic compatibility from its missing expiry. Neither field shape nor a 64-hex appearance enables either consumer. A stored SHA256 server key is never marked A1 compatible.

## Required evidence and offline files

Drain all old credential/account writers before collecting a final consistent snapshot. The operator must review the actual application revisions, namespace and per-record encoding. Capture source account credential fingerprints in the same drained snapshot. The fingerprint is SHA256 of UTF-8 `JSON.stringify(["yii-ar-account-v1", password_hash ?? null, auth_key ?? null])`; preserve null and empty distinctly. Never derive source evidence from the target account at import time.

The protected input envelope is `{version:1,source,capturedAt,accounts,entries}`. `capturedAt` is canonical UTC ISO with milliseconds, an observation time rather than issuance time. `source` requires `storage:"yii2-redis-active-record-hash"`, `redisDatabase:1`, `keyPrefix:"refresh_token:a:"`, reviewed 40-hex `a1Revision` and, for expanded/server-compatible records, `serverRevision`; `namespaceReviewed`, `keyEncodingReviewed`, `accountSnapshotReviewed`, `writersDrained` must all be true. `a1LookupReviewed` and `serverLookupReviewed` are explicit booleans.

`accounts` contains `{userId,accountFingerprint}` from the source snapshot. Each entry contains `{redisKey,type:"hash",pttl:-1,sourceKind:"a1"|"server",keyEncoding:"plain"|"sha256-hex",a1Compatible:boolean,serverCompatible:boolean,fields}`. Redis hash field values must be exact strings. A1 source records contain exactly `id,user_id,key`. Expanded server records allow `session_id,user_agent,ip,created_at,expires_at,revoked_at` in addition to those three fields. Existing expiry is copied exactly; missing expiry remains null. Unsupported Redis TTL, unknown fields, malformed IDs, duplicate credentials/record IDs, or any device provenance fields (including empty ones) fail closed. Device SN credentials need their existing provenance-aware migration and cannot become ordinary sessions.

Run the standalone exporter with protected owner-only regular files (maximum 64 MiB):

```sh
node dist/scripts/legacy-refresh-credential-export.js --snapshot=/protected/reviewed-snapshot.json --out=/protected/new-hash-manifest.json
```

It creates a new mode-0600 hash-only manifest and prints counts only. It does not connect to Redis or MySQL, output raw credentials/account evidence, overwrite an existing file, or prove a final cutover.

Apply the bundled `deploy/mysql/identity-legacy-refresh-credential-schema.sql` (also included in runtime schema and image DDL assets), then run the private-target importer before the Identity application activates authority:

```sh
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity node dist/scripts/legacy-refresh-credential-import.js --file=/protected/new-hash-manifest.json --dry-run
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity node dist/scripts/legacy-refresh-credential-import.js --file=/protected/new-hash-manifest.json --apply
```

Use the explicit private `IDENTITY_DB_*` target. There is no legacy DB fallback or runtime Redis access. Import performs no DDL. The apply transaction takes the existing one-way migration fence and private account locks. Source credential fingerprints must match the current private account. If a subject already has a revocation cutoff and the source provides no issuance ordering, both dry-run and apply require further review rather than guessing. This conservative rejection is not described as lossless migration. Existing credential rows/tombstones are never overwritten or reactivated. Any conflict rolls back the entire batch. Identity startup activates authority; a later apply is forbidden.

## Runtime boundaries

The trusted A1 PHP client sends `{refreshToken,allowLoginCode:false,consumer:"a1"}` to `POST /internal/yii3/refresh` using the configured internal auth key. Public/browser request fields must never be forwarded as `consumer`; the public `/v1/auth/refresh` always uses the default server policy, even if its body includes that field. y1 continues using its existing request shape and default policy.

The ledger classifies every imported credential, including expired, revoked and redeemed rows. Raw or wrapped known refresh credentials cannot fall back to a login code. Both offline import orders reject any digest shared with `identity_refresh_sessions`. Runtime native classification also takes precedence, and direct ledger redemption rejects a native digest, so a native revoked/rotated/OAuth/SN credential cannot become a new ordinary family. First exchange locks the private user and ledger row, checks live status/deletion/password/auth-key fingerprint/cutoff, reads current roles, then creates one ordinary native family in the same transaction. Its lifetime starts at this real native issuance and uses configured native TTL; that TTL is not fabricated historical source evidence.

The old credential cannot create another family. A short AES-256-GCM response replay is bound to credential digest, subject, consumer, session and original native successor. It requires the same still-live original successor and unchanged current account state. Anonymous retries last at most five seconds; a matching idempotency key lasts at most thirty seconds. Rotation, expiry, logout, changed credentials or cutoff disables replay. `IDENTITY_REFRESH_REPLAY_KEY` must canonically encode 32 random bytes as unpadded base64url or standard padded base64, matching existing native replay key deployments. Without it, first exchange can succeed but response replay is unavailable.

Native/legacy logout, all-session revocation, password change/reset, disable and delete update the ledger tombstone in their private transaction. Reimport preserves redemption/revocation. No path recreates an old family after logout, password change or reactivation.
