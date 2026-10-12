# Legacy profile selection

Native `user_info` retains `UNIQUE(user_id)` because runtime reads and writes
represent one current profile. Legacy Yii allowed several profile records per
user. Its `hasOne(user_id)` and the historical Identity reader both used
`LIMIT 1` without ordering. Migration must not guess the newest or oldest row.

The import reads every identity-profile row, preserves all of them in
`identity_legacy_profile_rows`, and adds immutable payload versions to
`identity_legacy_profile_history`. Those payloads contain original profile ID,
user ID, info and avatar reference. Business balances stay in the business
database, which is never changed. Only the explicitly selected record supplies
both canonical info and avatar; a selected NULL avatar remains NULL. Users with
no source profile receive no invented profile.

Source `info` must be a JSON column containing objects, arrays or SQL NULL.
mysql2 has already decoded these values. JSON scalar strings, numbers, booleans
and JSON null are rejected before migration, as are TEXT columns; they require
a separate reviewed encoding conversion. Dry-run returns
`PROFILE_INFO_SCALAR_UNSUPPORTED` or `PROFILE_INFO_ENCODING_UNSUPPORTED` without
printing profile contents. Sync also rejects scalar changes in private profiles
before baseline hashing. This prevents ambiguous strings from being parsed twice.

Apply the current `identity-account-schema.sql` before importing. It adds the
two archive tables without altering the runtime profile's unique constraint.
All account/provider imports must run while `identity_migration_control` is
staging, before native HTTP startup activates the one-way authority fence.

Capture a proposed selection from a read-only source, then review its counts,
selected profile IDs and equality of the two old read shapes:

```sh
node dist/scripts/profile-selection-capture.js --out=/tmp/profile-selection.json --max-rows=100000
node dist/scripts/account-import.js --dry-run --import-key=<unique-key> --profile-selection=/tmp/profile-selection.json
node dist/scripts/account-import.js --apply --import-key=<same-key> --profile-selection=/tmp/profile-selection.json
```

The protected manifest has exactly this structure:

```json
{"version":1,"selections":[{"userId":123,"profileId":456,"sourceRowsSha256":"<64 lowercase hexadecimal characters>"}]}
```

Only duplicate owner groups need entries on first import. The digest is
`profileGroupSha256(rows, hasAvatarColumn)`: sort the entire owner group by
numeric source profile ID; form objects in the order `id`, `user_id`, `info`,
`avatar_id`; convert IDs to decimal strings, retain NULL, recursively sort info
object keys; SHA256 the UTF-8 `JSON.stringify` result. The reviewed digest must
still match the source snapshot when importing; it is not a credential.

Dry-run uses the target's actual unique indexes and MySQL collations to detect
source collisions before any account insert. It does not fold Unicode in
JavaScript or silently ignore duplicate-key errors.

Account sync reuses the same projection and the committed archive's fixed
selection. Unselected edits update only the archive/history; selected edits
update canonical info/avatar. A disappearing selected row with other profiles
remaining requires a fresh reviewed manifest via `account-sync
--profile-selection=...`. Removing all profiles clears the current profile but
retains archive rows marked absent. Repeated unchanged sync is a no-op, and
untracked modifications to either canonical data or its archive fail baseline
validation. Every archive/canonical/baseline/history/outbox update belongs to
the same staging transaction.
