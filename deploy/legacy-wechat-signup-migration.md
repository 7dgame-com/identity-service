# Reviewed legacy WeChat signup credentials

This independent compatibility profile preserves a reviewed, ownerless Yii SQL `wechat.token` registration bearer. It grants only registration or password-authenticated existing-account binding. It is not an AR refresh token, login code or sign-in token. Historical timestamps do not imply expiry. An absent source expiry stays SQL NULL; an actual expiry or revocation is preserved, including expired/revoked tombstones.

Runtime is default off. Mount a protected trust file read-only and set `IDENTITY_LEGACY_WECHAT_SIGNUP_CONFIG_FILE`:

```json
{"version":1,"manifestSha256":"<canonical reviewed manifest SHA256>","providerAppId":"<exact reviewed provider application>"}
```

The trust pin covers the complete normalized manifest, including source proof and official exact-app evidence digests. Review the protected proof files independently before enabling the pin. Boolean review declarations and evidence hashes do not perform official verification themselves. Neither current configuration, equal openid/unionid, row age, nickname nor error/unfollowed responses prove a historical application's ownership. Official app-scoped user-info evidence must identify the exact case-sensitive openid and app; uncertain records must not enter this manifest.

The hash-only manifest contract is `legacyWechatSignupManifestSchema` in `legacy-wechat-signup-manifest.ts`. Required source evidence: `storage:yii2-mysql-wechat`, exact database/table, 40-hex source revision, drained writers, reviewed ownerless/lifetime/application declarations, `proofSha256`, and final capture time. Each row has source positive `recordId`, SHA256 of the exact raw legacy bearer, `userId:null`, exact official-account app/openid, original nullable created/updated/expiry/revocation timestamps, `expirySource:absent|expires_at`, and `providerProof:{kind:official-user-info,providerAppId,openId,verifiedAt,evidenceSha256}`. Timestamps are canonical ISO milliseconds UTC. No raw bearer, password, union-derived ownership or invented issuedAt is accepted. Source/provider evidence files and this manifest contain private information; protect them with owner-only permissions. Never send their contents to logs.

Apply `deploy/mysql/identity-legacy-wechat-signup-schema.sql` before import (the same CREATE is also included in `identity-runtime-schema.sql` and runtime bootstrap). The image ships both SQL and compiled CLI. The importer never creates tables, contacts old services, or activates authority.

```sh
node dist/scripts/legacy-wechat-signup-import.js --file=/protected/signup.json --inspect
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity IDENTITY_LEGACY_WECHAT_SIGNUP_CONFIG_FILE=/protected/signup-trust.json node dist/scripts/legacy-wechat-signup-import.js --file=/protected/signup.json --dry-run
NODE_ENV=staging IDENTITY_DATA_SOURCE=identity IDENTITY_LEGACY_WECHAT_SIGNUP_CONFIG_FILE=/protected/signup-trust.json node dist/scripts/legacy-wechat-signup-import.js --file=/protected/signup.json --apply
```

`--inspect` is offline and outputs only count and canonical manifest digest. Dry-run/apply connect only to the configured private Identity database. Apply requires the one-way migration authority fence to remain `staging`; finish the final account snapshot/sync first, then import signup credentials, and do not start native HTTP before completing imports. The signup import replaces the private compatibility row's raw bearer with an unrelated random native challenge; a later account sync would conflict with that intentional change. Reports are aggregate-only and `notFinal:true`. Reimport never resets consumed/revoked state. Existing owned/ambiguous provider rows, mismatched compatibility source IDs and other known credential hashes fail closed. No actual production snapshot is implied by fixture validation.

Public `/v1/wechat/refresh` retains pending `signup` UX for this bearer. `/v1/wechat/register` retains HTTP 200, `success/message/uid/token`; `/v1/wechat/binding` retains HTTP 200, `access_token/code:20000`. Registration uses the existing native password, username/email, profile, user-role and event policy. Binding requires the current password and account status, and never replaces another same-app identity. Account creation/binding, one-time consumption and original native session commit atomically. Lost-response retries replay the same encrypted response for at most 30 seconds, only for the exact original request and still-current account/family/successor. Stable `IDENTITY_REFRESH_REPLAY_KEY` is required. Rotation, logout, password mutation, disable/delete or family revocation prevents re-exchange. Source/raw compatibility tokens are not retained; a separate random challenge supports future native scans.
