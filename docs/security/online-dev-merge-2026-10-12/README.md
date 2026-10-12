# Online development merge verification, 2026-10-12

This candidate merges the independently verified baseline
`1377b39f5444b3ff57f05ab864a841bb7722f36a` with the actual GitHub development head
`14ba99cac16c6951322f1dd90b4fae9f0e0f64b2`. Their common ancestor is
`42ae9a13a91ee2c1b9c605df70e3d3f0d068d8dd`. The latter development revision is
also the observed running online development build; the candidate does not
replace it with an older diverged implementation. Both lines remain in history.

The merged implementation preserves device SN session provenance, the original
maximum three-hour access lifetime, source revalidation and restrictions on
deriving other credentials. In native mode business `device_sn` has a separate
read-only connection; current accounts and inherited role eligibility come from
the private Identity database. Ordinary historical sessions with both source
columns NULL remain valid. Refresh successors inherit their stored source and
session family, including concurrent retries. Organization login events,
current member authorization, IP visibility and daily invoices use native
private accounts and active sessions when independent authority is selected.
Legacy mode retains the previous deployment paths.

Native standard OIDC grants now bind their client and original scope ceiling to
the private session in the same transaction. Refresh checks that binding before
consuming a credential; ordinary login, WeChat OAuth, device SN and other client
credentials cannot be exchanged. Userinfo verifies the audience from its stored
client binding and returns only signed, permitted scopes. Bound sessions are
also excluded from generic Native access, including when a configured client ID
matches the API audience. Legacy protocol behavior remains unchanged.

The remote lock already advanced `@nestjs/platform-express` to 11.2.6; that
version is retained rather than downgraded to the independent baseline.
Compatible security floors and overrides from the baseline are preserved, and
the declared `mysql2` floor now matches the installed fixed 3.24.5 release.
No dependency crosses a major version. A standard `npm ci` without peer resolver
overrides reconstructed the tree successfully. Both accompanying audit reports
have **zero findings** and contain only public package metadata, not credentials.

| Evidence | Value |
| --- | --- |
| Lock SHA-256 | `6e006bd79bff3cfc88ddc3c317f6ce2449efb24c67d777b4ea0e5ad772148d9d` |
| Production audit | `npm audit --omit=dev --json`: 0 |
| Complete CI audit | `npm audit --json`: 0 |
| TypeScript | `tsc --noEmit`: passed |
| Complete regression, `TZ=Asia/Shanghai` | 85 files / 1350 tests passed; 0 failed or skipped |
| Disposable MySQL 8.4.11 coverage | 19 files / 210 tests passed (baseline 167 plus 43 additional cases) |

The [baseline audit](../npm-audit-2026-10-12/README.md) records the original
findings and official fixed versions. These new reports identify the merged
lock; the baseline's old reports are retained as historical evidence.

Use the CI workflow's disposable MySQL service and its three fixture environment
families (`IDENTITY_DB_*` / `IDENTITY_TEST_MYSQL_*`, `LOGIN_EVENTS_MYSQL_TEST_*`,
`DEVICE_SN_MYSQL_TEST_*`) for the complete regression. Individual fixtures create
random databases; they must never use application or production principals.
The native SN fixture deliberately lacks business account/RBAC tables, and the
native organization/OIDC fixtures make the old account database unreachable.
OIDC coverage verifies that an authorization-code exchange without
`offline_access` still has a tracked, revocable native access session while
returning no refresh credential. External Apple/WeChat providers and online
MySQL 8.0.30-cynos require separate environment verification; local fixtures do
not establish their availability.

The release image must be rebuilt from this clean merge commit for
`linux/amd64`, with its exact SHA compiled as `BUILD_REVISION`. Publishing and
online authority activation are separate actions. A local image ID is not a
registry manifest digest.
