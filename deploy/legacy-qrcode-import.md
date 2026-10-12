# Preserve pending QR login during staging

The offline converter/importer is `scripts/legacy-qrcode-import.ts`. It opens no
Redis connection. `--export` reads an already captured JSON snapshot and writes a
new digest-only manifest with mode `0600`, refusing to overwrite an existing file.
The default import is a dry run. Apply requires both `NODE_ENV=staging` and the
persisted private database authority to remain `staging`; activation permanently
fences subsequent apply attempts. Import after the final drained account snapshot
and before native Identity bootstrap. Never export or print QR credentials into
application logs.

```sh
node dist/scripts/legacy-qrcode-import.js --file=/secure/offline-snapshot.json --export=/secure/qr-manifest.json
node dist/scripts/legacy-qrcode-import.js --file=/secure/qr-manifest.json --dry-run
NODE_ENV=staging node dist/scripts/legacy-qrcode-import.js --file=/secure/qr-manifest.json --apply
```

Apply `identity-qrcode-schema.sql` before importing. For a staging database that
already had the earlier QR schema, add its new metadata column once:

```sql
ALTER TABLE identity_login_codes ADD COLUMN context_json JSON NULL;
```

The offline snapshot envelope is:

```json
{
  "version": 1,
  "captured_at_ms": 1780000010000,
  "login_code_read_mode": "database",
  "user_linked": [],
  "redis_login_codes": [],
  "pending_wechat_scenes": [],
  "redis_open_ids": [],
  "wechat_scenes": []
}
```

`captured_at_ms` is the original snapshot capture time, never the later import time.
Use the active legacy read mode (`database`, `redis`, or `redis-first`). All arrays
may be empty. The converter accepts at most 100000 source records; the CLI rejects
files above 64 MiB. No import changes the original expiry, issues an access or refresh
token, creates an account, or marks a code consumed. Replaying an existing row skips
it without extending its deadline, replacing its actor or reviving an inactive row.
The whole apply batch, including staging-fence lock, is one MySQL transaction.

## Yii device codes

The actual legacy table is `user_linked`, despite the endpoint being named
`tools/user-linked`. Its snapshot rows contain `id`, integer `user_id`, `key`,
explicit `key_encoding` (`plain` or `sha256-hex`) and `created_at` in
`YYYY-MM-DD HH:mm:ss` format. The latter is explicitly Asia/Shanghai wall time,
matching `LoginCodeSettings::LEGACY_DB_TIME_ZONE`; the converter never depends on
the machine or MySQL session time zone. It selects the largest row ID per user to
preserve legacy "latest code wins" and keeps its original 60-second window.

Yii Redis v1 snapshot rows contain `key`, `value`, `pttl_ms` and `redis_time_ms`.
`key` has the actual `<configured-prefix>:code:<sha256-hex>` form. `value` is the
JSON value or its decoded object, with exact `v:1`, `user_id`, `issued_at`,
`expires_at`, `purpose:"web-device-login"`, `issuer:"main-api"`, and `context`.
Capture GET, PTTL and Redis TIME atomically from an **isolated restored copy** or
an explicitly reviewed production snapshot process. These instructions do not
authorize connecting this task to production Redis.

Redis's 300-second TTL is record retention, while authorization lasts 60 seconds.
The converter caps authorization at the earlier of the record expiry and
`redis_time_ms + max(0, PTTL - 240000)`; it rounds down to seconds. Missing/persistent
TTL, malformed records and future issue times fail closed. Every valid Redis code
is retained, preserving several simultaneous device codes. A Redis-first hit that
has expired never falls back to the still-current DB shadow. `context` metadata is
retained without introducing new issuer or audience behavior; current Yii issuance
does not consume `resolved.frontend_domain`.

## WeChat scene evidence

Each `wechat_scenes` snapshot row contains `source`, `token`, optional identical
`scene`, exact `provider_app_id`, `openid` (null only for a ticket not yet scanned),
UTC ISO `created_at` and `expires_at`, and explicit UTC ISO/null `consumed_at`.
Optional `user_id` is the **canonical integer ID**, never the auth-service UUID;
`signup_token` and `profile_json` preserve already returned pending registration
state. Imported profile provider and open ID must match the scene exactly. Existing
private provider mappings are checked for conflicts and existing pending
`wechat.token` hashes are reused, never replaced.

Supported evidence sources:

- `auth-mysql`: an actual `auth_legacy_scan_tokens` row. Preserve its original
  `created_at`, `expires_at` and `consumed_at`; do not replace them with capture time.
- `redis-with-ticket-evidence`: an actual Yii Redis `open_id` hash plus separately
  recorded trustworthy issue/expiry and official app evidence. Include `redis_key`
  in the exact `open_id:a:<yii-key>` form; the converter validates Yii's <=32-byte
  alphanumeric-or-MD5 key rule against its stored token.
- `ticket-evidence`: a still-pending scene proven by an issued ticket manifest or
  equivalent trusted record, with `openid:null` and its exact original deadline.

Consumed scenes remain inactive. Scene lifetimes above the provider's existing
30-day request bound, unknown app IDs,
conflicting subjects, or missing expiry evidence are rejected. A MySQL scan's
expiry represents the legacy state window; a pending ticket manifest must represent
the original ticket deadline.

## Compatibility baseline: preserve unscanned tickets without refreshing the UI

Before any final switch, release the legacy-compatible issuer change that records
every newly delivered WeChat scene **at generation time**, while keeping the
existing QR response unchanged. Its pending metadata has only a SHA-256 scene
digest, provider app and exact original issue/expiry; it is not proof that a user
has scanned. Native signature validation remains required on the later callback.

The auth-service storage contract is `auth_legacy_scene_metadata` with
`scene_digest`, `provider_app_id`, UTC `issued_at`, UTC `expires_at`; the Redis
equivalent is `identity:legacy_scene:<sha256hex>` with the same fields and
`PEXPIREAT` at the original deadline. Export these records into
`pending_wechat_scenes`, rendering both times as UTC ISO strings. The converter
also accepts the equivalent `{scene_hash,provider_app_id,issued_at,expires_at}`
with epoch seconds. It imports the digest directly, so recovering or storing a
pending scene's plaintext is unnecessary.

Yii's corresponding table is `identity_legacy_wechat_scenes`, with `scene_hash`,
`provider_app_id`, integer `issued_at`/`expires_at`, and `source`; that actual row
shape is accepted directly. Run its schema migration, then enable
`IDENTITY_CAPTURE_LEGACY_QR_SCENES=true` on every PHP issuer for the compatibility
baseline. The default remains false. Scanning does not convert metadata alone into
user proof, and placeholder app IDs such as `unknown` or `legacy-redis` are rejected.

For scanned Redis state, include actual `{key,token,openid}` hash records in
`redis_open_ids`. The converter validates the Yii key rule and joins the token
digest to captured pending metadata to obtain its provider and exact deadline.
No matching issuance metadata means rejection. Do not feed the Redis `open_id`
index's historical duplicates or unsupported stale entries as valid current
tickets. For scanned MySQL state, use the actual scan record in `wechat_scenes`;
its already validated, original state window is preserved separately from the
still-pending ticket window.

All actual issuers must run this baseline successfully for at least their
**longest configured ticket lifetime** before final cutover. Yii's site QR path
currently requests six days, its API QR path requests one hour, and auth-service
uses `AUTH_LEGACY_SCAN_TOKEN_TTL_SECONDS` (default one hour). Inventory overrides,
the backend QR entry point and every deployment before choosing the wait; do not
assume six days is sufficient if configuration allows a longer ticket. Start the
wait after the last issuer has the compatibility release and verified metadata
delivery. A failed or bypassed metadata write restarts that issuer's completeness
window. This preparation is a release prerequisite, not an action performed by
the offline importer.

After the completeness window, drain **all** old issue, scan, poll and account
write paths; export a consistent final account/pending/scan/session snapshot,
import its staging delta, then switch callback and poll routes together. The
original scene stays on screen and its digest resolves in Identity, so the user
does not need to rescan. Preserve provider callback routing and exact app proof.
Do not activate native authority before staging imports, preflight and elapsed
budget checks complete. A failure **before** persisted activation cancels the
switch and permits resuming the legacy sole writer. After native bootstrap has
persisted `authority=identity`, a routing or health failure must continue recovery
against Identity; it must never reopen legacy account writes. Treat activation as
the one-way commit point and rehearse that recovery path.

## Evidence that cannot be reconstructed

`backend/auth-service/src/legacy-routes.ts` generates a random `/wechat/qrcode`
scene but does not persist it until a signed scan callback. Its Redis adapter in
`src/legacy-redis.ts` stores only `token` and `openid`, with no `EXPIRE`, creation
time or provider app. `mysql-store.ts::findLegacyScanToken` fabricates a 9999 expiry
for that Redis path. Those values cannot prove an original deadline, and the
converter intentionally refuses to invent one. Pending scene IDs absent from every
snapshot cannot be recovered by an importer.

The completeness wait above lets every previously unrecorded ticket expire while
legacy remains the sole authority and newly delivered tickets become recoverable.
Do not cut over early, accept arbitrary unknown scenes, fabricate missing expiry,
or force users to reload their QR screen as a substitute for this preparation.
The non-expiring historical Redis hashes still cannot establish active validity;
their synthetic 9999 deadline remains rejected.

## Private WeChat scope upgrade

Existing private Identity databases must apply
`mysql/identity-wechat-binary-migration.sql` before native traffic. Fresh schemas
already use binary comparisons for application IDs, openids, union IDs and
registration tokens. Run this DDL outside an import transaction and never against
the legacy business database. It changes collation only and preserves proof
digests, account IDs and expiry values.

The exact `(provider, app ID, openid)` binding is authoritative. A global legacy
`wechat.openid` or `user.wx_openid` alone cannot establish ownership in a new
application. Import reviewed application-scoped account mappings before cutover;
accounts with only an unscoped old mapping and no provider-verified union ID are
rejected for reconciliation. Existing-account password binding can explicitly
attach a second application while retaining the scalar compatibility projection.
Confirmed scene signup digests remain available for same-account retries only
until their original expiry; status polling never extends that deadline.
