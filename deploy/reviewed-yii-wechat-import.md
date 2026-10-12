# Reviewed Yii WeChat account bindings

Yii stores `wechat.openid` and `user.wx_openid` without an application ID. Native
Identity cannot safely infer which application owns those identifiers. Prepare an
operator-reviewed mapping before cutover so existing Yii users can keep using
their original WeChat account. Do not infer app IDs from an openid, email,
nickname, a default provider setting or an unrelated deployment.

The shared `scripts/wechat-identity-import.ts` tool accepts `--yii-manifest` for
this mapping. Its original auth-service UUID import remains available without
that option. Both modes require the private binary schema upgrade first. The Yii
mode reads a consistent, read-only snapshot of the original Yii database, holds
the private staging fence until commit, and writes only exact provider bindings,
import records and ordered subject events. It never changes old or private
account IDs, passwords, compatibility `wechat` rows, session credentials or QR
deadlines.

## Prepare and review the manifest

Export account identifiers from the correct old Yii deployment using read-only
access. Associate each row with its actual provider type and application ID from
that deployment's reviewed configuration and ownership records. Keep this file
private with mode `0600`; it contains provider identifiers, but no passwords,
refresh tokens, app secrets or raw QR scenes.

```json
{
  "schema_version": 1,
  "source_database": "old_yii_database",
  "review": {
    "reference": "approved-cutover-review-17",
    "reviewed_by": "migration-owner",
    "reviewed_at": "2026-10-12T00:00:00.000Z"
  },
  "bindings": [
    {
      "provider": "wechat_official_account",
      "provider_app_id": "reviewed-actual-app-id",
      "open_id": "exact-case-sensitive-old-openid",
      "user_id": 7001,
      "evidence": "wechat",
      "union_id": null
    }
  ]
}
```

`evidence: "wechat"` requires one exact old `wechat.openid` row with the same
integer `user_id`. If a union ID is supplied, that old row must contain exactly
the same value. `evidence: "user.wx_openid"` requires exactly one old user with
that case-sensitive scalar value and the same ID; union ID must be null in that
mode. The application ID and provider type always require explicit human review;
these old columns cannot prove them. Missing review metadata, duplicate tuples,
conflicting account/application mappings and batch limit violations are rejected.

## Rehearse and cut over

1. Publish the legacy QR metadata compatibility baseline and complete its actual
   maximum-ticket-lifetime wait as described in `legacy-qrcode-import.md`.
2. Create the private DB and apply account, runtime, QR and WeChat OAuth schemas.
   For an existing private DB, run `mysql/identity-wechat-binary-migration.sql`
   outside an import transaction before this tool. Never run that DDL on the old
   business DB. Both fresh and upgraded private identifier columns must use
   `utf8mb4_bin`.
3. Import/synchronize the complete Yii account snapshot, preserving its integer
   IDs. Rehearse this tool against disposable copies using its default dry-run.
4. During final writer/issuer/callback/poll drain, apply the final account delta,
   then this reviewed Yii mapping, then auth-service UUID/provider mappings,
   then final QR and refresh-session manifests. Run the final account delta before
   OAuth-only accounts are created. No importer may run after native bootstrap
   permanently sets `authority=identity`.
5. Verify existing Yii WeChat login, auth-service SSO and old on-screen QR login
   using their original credentials before accepting traffic. Budget cancellation
   may resume legacy writes only before the one-way native authority activation.

Configure the old Yii database as `LEGACY_DB_*` and the private database
as `IDENTITY_DB_*`; the existing connection helper uses UTC timestamps and should
use a read-only source principal. Database names must differ. Example commands
from the Identity service directory:

```bash
node node_modules/tsx/dist/cli.mjs scripts/wechat-identity-import.ts \
  --yii-manifest=/secure/reviewed-yii-wechat.json \
  --import-key=cutover-yii-wechat-17 --max-rows=10000

node node_modules/tsx/dist/cli.mjs scripts/wechat-identity-import.ts \
  --yii-manifest=/secure/reviewed-yii-wechat.json \
  --import-key=cutover-yii-wechat-17 --max-rows=10000 --apply
```

The default is dry-run; `--dry-run` takes precedence over `--apply`. Output contains
counts only. Repeating an applied key with the identical reviewed manifest makes
no writes. Reusing the key with another manifest fails. The tool rejects both
dry-run and apply after authority activation. Any target mapping conflict rolls
back the complete batch; resolve the reviewed ownership evidence before retrying.

Auth-service UUID import now resolves canonical accounts through an existing exact
reviewed provider binding or an explicitly verified, case-sensitive union ID.
An unscoped Yii openid with an owner cannot silently merge a UUID account into
that owner. Import the reviewed Yii binding first; the UUID then maps to the same
integer account without forcing the user to register again.
