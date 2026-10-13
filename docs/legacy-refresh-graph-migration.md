# Reviewed full-response refresh graph migration

This optional protocol imports annotated Y1 and shared A1/PHP AR state into the private Identity database. It does not replace the existing unannotated legacy credential/session importers. It is default-off and does not prove that writers have drained, that source keys have been captured, or that the production cutover is ready.

## Assets and readiness

Apply the separate `deploy/mysql/identity-legacy-refresh-graph-schema.sql` explicitly while Native HTTP is sealed/stopped and authority is staging. It creates exactly three optional tables: families, hash-only credentials/tombstones, and encrypted responses. It contains no seed, ALTER, GRANT, account mutation or activation. Frozen runtime/account/allocator assets are unchanged. Runtime never ensures or creates graph schema; when enabled, bootstrap reads its required columns and unique indexes. Optional graph tables participate in the allocator's actual namespace/reference checks without expanding its frozen required formal-table list.

`IDENTITY_LEGACY_REFRESH_GRAPH_ENABLED=true` enables redemption. Default is `false`; malformed values are rejected. A retained graph hash remains classified when disabled and returns unavailable rather than falling through to an ordinary refresh or a login code. Classification also persists after consumption, expiration and revocation. The private `IDENTITY_REFRESH_REPLAY_KEY` must canonically encode exactly 32 bytes; source and target replay encryption keys are distinct inputs and are never generated, derived, logged or written into manifests by this tool.

## Offline files

The strict schemas are exported by `legacy-refresh-graph-manifest.ts`:

- Manifest version `legacy-refresh-graph-v1`, protocol `yii3` or `ar`, Redis capture millisecond instant and reviewed source provenance. Source records actual 40-character revisions, Redis DB1, exact raw/metadata prefixes, source MySQL schema/UUID, account snapshot SHA, raw snapshot SHA, namespace review SHA and final drain review SHA. A preflight envelope or an operator's assertion alone is not a final graph.
- A separately captured, bounded owner-only file version `legacy-refresh-accounts-v1`: actual current source database `bujiaban_development`, server UUID, capture instant, and each current `{userId,status,accountFingerprint,accountEpoch,securityChangedAtMs}`. The whole file's exact raw-byte SHA is bound into the reviewed manifest. `accountEpoch` is a canonical UINT64 decimal string read from current `identity_legacy_security_versions`; metadata's old value cannot substitute for it. `securityChangedAtMs` is null only for epoch1; higher epochs require the actual ledger `updated_at` UTC millisecond instant at or before capture. The importer monotonically merges that SQL security cutoff with source Redis and existing private cutoffs, so a nonindexed old JWT cannot survive a raw SQL password/auth-key/status ABA. Source SQL is sampled before the final Redis graph within 60 seconds, with clock-window evidence retained by the source exporter. The importer itself makes no source or Redis connection.
- Full families are mandatory, including current hash, original expiry, and effective family revocation. A naturally expired/missing Y1 family is represented as `available:false,currentHash:null,expiresAtMs:null`; its persistent credential tombstones remain classified and unusable. No expiry is invented. A family invalidated by current SQL fingerprint/epoch/status or current Redis user epoch imports as locally revoked while retaining the unchanged source fact. An owner missing from the current private account store is an explicit unsupported-stop; source metadata cannot invent a current account.
- A target user revocation at or after the captured source account observation also imports the family as locally revoked. It cannot be adopted as a fresh permissive baseline. An earlier source Redis revocation remains compatible with a valid family at the current higher user epoch; exact import replay never clears a private revocation.
- Each hash-only credential records exact owner, family, security fingerprint, SQL/Redis epochs, paired SN provenance, original lifetime, original state/edge, exact source row hash, physical source-record presence, and explicit plaintext/hash lookup capabilities. Y1 source credentials retain their verified 30-day SETEX issuance/expiry. AR issuance is nullable and permanent expiry remains null. Duplicate IDs/hashes, cycles, foreign edges, missing owners and conflicting source facts are rejected. Every credential in a family must retain exactly the same SN context; both rotation edges and permanent A1 forks cannot remove or change it. Y1 user epoch0 is equivalent to a null revocation instant; higher epochs require the true source time. AR initial epoch1/null remains valid.
- Each response includes its actual P/S, owner/family/security state, original request hash, original creation/absolute retry deadline, decrypted complete canonical body **and original source AES-GCM ciphertext**. Source MAC and reviewed source JWT signer are verified before any response is accepted, then the body is re-encrypted under the private key with new protocol/consumer/scope/P/S/owner/epoch/fingerprint/request/deadline AAD. Raw refresh values and JWTs exist only inside protected input and encrypted response storage; database credential indexes remain hash-only. Import does not issue a session or re-sign an old JWT.

Current source account changes may leave otherwise structurally valid old active metadata. They must not be silently omitted or changed into a fabricated source revoke event. The importer retains those rows with a local revoked family. Active SN credentials additionally require independent current business-device authorization; no old account database fallback is used.

## Real source scopes

Y1's source cache stores one canonical `{token,nickname,user}` pair shared by `/v1/auth/refresh` and `/v2/auth/refresh-token`. Its AES AAD never recorded a public route or outer HTTP envelope. The graph therefore records `consumer:"yii3",endpoint:"y1-refresh-pair",issuer:null`. It does not fabricate an original public route. The Y1 wrapper selects its existing fixed v1/v2 envelope from its own trusted controller and preserves the original canonical values.

AR cache AAD really binds `consumer:"a1"|"server"`, exact endpoint (`/v1/auth/refresh` or A1 `/v1/common/report`) and exact source issuer. These scopes stay separate. A1 P remains reusable and new A1 S remains permanent/reusable; a PHP consume marks P consumed and immediately invalidates every A1 retry on P, including a previously live cache. PHP may replay only its matching consumed-P response while its S/family remain active. Y1 P rotation preserves its S edge and can replay only while S is still the active current family credential. A source response that is cryptographically authentic but whose S has rotated to T is retained evidence, not an effective replay.

The original 30-second keyed / 5-second unkeyed retry deadlines are absolute and never renewed by import. Reviewed source signer trust must cover the complete original retry window. Y1 keeps its original short other-key/absent-key fallback: null/null is never the keyed 30-second match; AR caches remain exact per consumer/endpoint/request. Original response `expires` is a bounded display string preserved unchanged; JWT `exp` and original graph deadlines authorize use. Internal `authTokens.expires` is separately derived from the verified JWT `exp` as UTC ISO. New finite successors follow the configured Native refresh policy; new A1 graph successors preserve permanent semantics even after their finite private access/revocation backing row expires. Native fresh display dates follow the existing wrappers' Asia/Shanghai format.

## Import command

Default dry-run performs all structural, source MAC/JWT, owner, conflict, SN and schema checks inside a rolled-back private transaction. It emits counts and manifest SHA only. Apply requires exact staging authority under the migration fence, `NODE_ENV=staging` and the exact reviewed manifest file SHA. It invalidates an allocator proof only immediately before actual mutations; an exact replay does not reset target revocation or create new sessions. Apply may not run after authority is Identity. Existing ordinary credentials that have already been exchanged/revoked cannot be revived by overlaying graph metadata.

```sh
# Protected files remain on the approved host. No source keys belong on the command line.
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity \
node dist/scripts/legacy-refresh-graph-import.js \
  --file=/protected/final-reviewed-graph.json \
  --accounts=/protected/current-source-security.json --dry-run

# After review, same immutable files and source trust; no automatic retry on uncertainty.
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity \
node dist/scripts/legacy-refresh-graph-import.js \
  --file=/protected/final-reviewed-graph.json \
  --accounts=/protected/current-source-security.json \
  --apply --reviewed-sha256=<exact-raw-file-sha256>
```

The production CLI is fixed to `10.206.0.5:3306/xrugc_identity_dev` and `identity_dev@%`; no cloud operation is performed by its tests. Source response authentication uses explicitly supplied `IDENTITY_LEGACY_YII3_RESPONSE_KEY` or independent `IDENTITY_LEGACY_A1_RESPONSE_KEY` and `IDENTITY_LEGACY_SERVER_RESPONSE_KEY` as applicable, and independently reviewed bounded source JWT trust files. Keys are selected only from the authenticated replay consumer; a missing consumer key never falls back to another consumer or JWT material. Only the library retains an explicitly provided common-key compatibility parameter. Missing keys/trust fail closed. Input files must be bounded owner-only regular files opened without following symlinks. SQL errors/input contents are not printed. DDL is a separate reviewed step; this CLI has no DDL, cleanup, grants or activation path.

## Authenticated bridge response

`POST /internal/yii3/refresh` retains the existing auth-scoped internal token and input `{refreshToken,allowLoginCode}`. A1 wrappers additionally send fixed `consumer:"a1",allowLoginCode:false,sourceEndpoint:"/v1/auth/refresh"|"/v1/common/report"`. Y1 wrappers omit consumer and may send their fixed `/v1/auth/refresh` or `/v2/auth/refresh-token`; both select the actual shared source scope. Consumer/scope never come from public request bodies and never change JWT audience. Public `/v1/auth/refresh` always uses the server scope.

A graph result preserves the existing `{authTokens,subject}` plus:

```json
{"legacyResponse":{"version":"legacy-refresh-response-v1","consumer":"yii3","endpoint":"y1-refresh-pair","body":{"token":{"accessToken":"<original>","expires":"<original display>","refreshToken":"<original>"},"nickname":"<original>","user":{"id":42,"username":"<original>","nickname":"<original>","fixture":false}}}}
```

Wrappers must validate exact version/consumer/scope, complete body shape, body access/refresh equality with standard `authTokens`, and owner equality where present. Current subject verifies live status/roles/owner but does not replace cached nickname/user/token display data. Original bodies are returned only inside their verified live retry window; fresh redemptions construct the existing consumer shape with fresh tokens.

HTTP graph request keys hash the exact latin1 wire bytes as PHP does, accept 1..256 bytes without C0/DEL or trimming, and reject duplicate wire headers. Direct library strings retain UTF8 semantics. Native ordinary-session replay behavior is unchanged. Proxy/framework header normalization is part of the final source deployment evidence, not invented by the importer.

## Remaining deployment gates

A real versioned final exporter must capture persistent tombstones, complete families/edges, physical credential presence, source ciphertext, current Redis user revocation and separately current SQL ledger/fingerprint after all actual writers drain. A Y1 preflight can establish local consistency but cannot claim a final drain or emit an importable final graph without that integration. Shared AR export additionally needs reviewed whole-row/hash-encoding evidence for all A1/PHP consumers. Neither exporter nor actual source credentials are supplied by this Native patch.

Source issuer profiles, source stable keys, full consumer/writer inventory, source backfill completeness, protected final files, standalone schema preparation, wrapper deployment and bounded admission/activation are separate required evidence. This patch is tested locally and does not claim a cloud capture/import, live migration or zero user-visible interruption. Unannotated old access JWTs with no retained response cannot be assigned to an invented family; they retain the existing bounded signer/user-cutoff compatibility policy.
