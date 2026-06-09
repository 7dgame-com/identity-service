# Phase 5 Account Lifecycle Runbook

Phase 5 starts with a compatibility bridge. The bridge is safe to deploy while
disabled and does not change current registration, password, email or invitation
flows.

## Default Safe State

Keep these values unless a scoped gray test is actively running:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=false
IDENTITY_ACCOUNT_LIFECYCLE_MODE=disabled
IDENTITY_ACCOUNT_REGISTER_ENABLED=false
IDENTITY_ACCOUNT_PASSWORD_ENABLED=false
IDENTITY_ACCOUNT_EMAIL_ENABLED=false
IDENTITY_ACCOUNT_INVITATION_ENABLED=false
IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED=false
IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED=false
IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=false
```

Verify:

```bash
curl http://127.0.0.1:8086/internal/account-lifecycle/readiness
```

Expected:

```json
{
  "status": "ok",
  "capability": "account-lifecycle",
  "data": {
    "enabled": false,
    "mode": "disabled"
  }
}
```

## Dev Legacy Proxy Test

Enable exactly one scope:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=legacy-proxy
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_REGISTER_ENABLED=true
```

The legacy backend URL must resolve to a backend that still runs lifecycle
provider `legacy`. The proxy adds `X-Identity-Lifecycle-Proxy: 1`; the main
backend uses that marker to avoid proxy loops.

## Dev Native Register Test

Enable only register native after proxy routing and token issuance have already
passed:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_REGISTER_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_ENABLED=false
IDENTITY_ACCOUNT_EMAIL_ENABLED=false
IDENTITY_ACCOUNT_INVITATION_ENABLED=false
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
LEGACY_WRITE_DB_HOST=10.206.0.14
LEGACY_WRITE_DB_PORT=3306
LEGACY_WRITE_DB_NAME=bujiaban_development
LEGACY_WRITE_DB_USER=identity_writer
LEGACY_WRITE_DB_PASSWORD=...
```

Verify readiness includes `"nativeRegisterConfigured": true`.

Native register writes:

- `user`
- `user_info`
- `auth_assignment`
- `wechat.user_id` for `/v1/wechat/register`
- `account_lifecycle_operations` for register idempotency and audit

Do not enable native invitation/register-send-code in this step. Invitation
quota and email verification remain legacy until their own native specs are
implemented and tested.

## Dev Native Password Change Test

Enable password change native only after identity token issuance is already in
use:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_PASSWORD_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED=true
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
LEGACY_WRITE_DB_HOST=10.206.0.14
LEGACY_WRITE_DB_PORT=3306
LEGACY_WRITE_DB_NAME=bujiaban_development
LEGACY_WRITE_DB_USER=identity_writer
LEGACY_WRITE_DB_PASSWORD=...
```

Verify readiness includes `"nativePasswordChangeConfigured": true`.

Native password change covers only:

- `POST /v1/password/change`

The following remain legacy/proxy:

- `POST /v1/password/request-reset`, unless reset native is enabled separately.
- `POST /v1/password/verify-code`, unless reset native is enabled separately.
- `POST /v1/password/reset`, unless reset native is enabled separately.

Expected successful response:

```json
{
  "success": true,
  "message": "密码修改成功，请重新登录"
}
```

## Dev Native Password Reset Test

Enable reset native only after a mail webhook is ready:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_PASSWORD_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_WEBHOOK_TOKEN=...
IDENTITY_PASSWORD_RESET_CODE_HASH_SALT=...
```

Verify readiness includes `"nativePasswordResetConfigured": true`.

Native password reset covers:

- `POST /v1/password/request-reset`
- `POST /v1/password/verify-code`
- `POST /v1/password/reset`

Do not enable reset native if the webhook cannot deliver email in the target
environment. Leaving `IDENTITY_EMAIL_WEBHOOK_URL` empty is an intentional safety
gate.

## Dev Legacy Refresh Session Compensation Test

Enable this only after native password change/reset are already green:

```bash
IDENTITY_LEGACY_SESSION_REVOKE_ENABLED=true
IDENTITY_LEGACY_SESSION_REVOKE_URL=http://backend-api/v1/internal-identity/revoke-sessions
IDENTITY_LEGACY_SESSION_REVOKE_TOKEN=<internal-service-token>
IDENTITY_LEGACY_SESSION_REVOKE_TIMEOUT_MS=800
```

Main backend:

```bash
IDENTITY_ACCOUNT_INTERNAL_TOKEN=<internal-service-token>
```

Safety behavior:

- The main backend endpoint is `POST /v1/internal-identity/revoke-sessions`.
- It requires `X-Identity-Internal-Token`.
- It only accepts numeric `legacyUserId`.
- It only calls `SessionService::revokeUserSessions($legacyUserId)`.
- identity-service treats this as compensation; failure is logged and does not
  fail password change/reset responses.

## Dev Native Email Verification Test

Enable basic email verification native only after identity token issuance and
mail webhook delivery have passed:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_EMAIL_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=true
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_WEBHOOK_TOKEN=...
IDENTITY_EMAIL_CODE_HASH_SALT=...
LEGACY_WRITE_DB_HOST=10.206.0.14
LEGACY_WRITE_DB_PORT=3306
LEGACY_WRITE_DB_NAME=bujiaban_development
LEGACY_WRITE_DB_USER=identity_writer
LEGACY_WRITE_DB_PASSWORD=...
```

Verify readiness includes `"nativeEmailVerifyConfigured": true`.

Native email verification covers only:

- `GET /v1/email/status`
- `POST /v1/email/send-verification`
- `POST /v1/email/verify`
- `GET /v1/email/cooldown`

## Dev Native Email Change/Unbind Test

Enable this only after basic email verification native is already passing:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_EMAIL_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED=true
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_WEBHOOK_TOKEN=...
IDENTITY_EMAIL_CHANGE_TOKEN_TTL_SECONDS=600
LEGACY_WRITE_DB_HOST=10.206.0.14
LEGACY_WRITE_DB_PORT=3306
LEGACY_WRITE_DB_NAME=bujiaban_development
LEGACY_WRITE_DB_USER=identity_writer
LEGACY_WRITE_DB_PASSWORD=...
```

Verify readiness includes `"nativeEmailChangeConfigured": true`.

Native email change covers:

- `POST /v1/email/send-change-confirmation`
- `POST /v1/email/verify-change-confirmation`
- `POST /v1/email/unbind`
- `POST /v1/email/verify` with `change_token`

Safety behavior:

- `send-change-confirmation` sends a 6-digit code to the currently verified
  email.
- `verify-change-confirmation` consumes that code and returns a 10 minute
  `change_token`.
- New verified-email binding requires both the new-email code and the
  `change_token`.
- Verified-email unbind requires the current-email 6-digit code, matching the
  current frontend API call.
- Unverified-email unbind can proceed without a code.
- Disable `IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED` to return change and
  unbind paths to legacy/proxy while leaving basic email verification native
  enabled.

## Dev Invitation Diagnostics Test

Before any invitation native implementation, run readonly reconciliation:

```bash
IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED=true
IDENTITY_INTERNAL_API_TOKEN=<internal-service-token>
IDENTITY_INVITATION_REDIS_URL=redis://10.206.16.15:6379/0
LEGACY_DB_HOST=10.206.0.14
LEGACY_DB_PORT=3306
LEGACY_DB_NAME=bujiaban_development
LEGACY_DB_USER=identity_readonly
LEGACY_DB_PASSWORD=...
```

Check all invitations:

```bash
curl -H "X-Identity-Internal-Token: <internal-service-token>" \
  http://127.0.0.1:8086/internal/account-lifecycle/invitations/diagnostics
```

Check one invitation:

```bash
curl -H "X-Identity-Internal-Token: <internal-service-token>" \
  "http://127.0.0.1:8086/internal/account-lifecycle/invitations/diagnostics?code=<invite-code>"
```

This endpoint is internal-only and readonly. Do not expose it through public
Traefik routes. See `docs/runbooks/invitation-reconciliation.md` for the field
map and remediation notes.

After diagnostics is clean, preview Redis-to-identity import:

```bash
npm run invitation:import -- --dry-run
```

Only after the dry-run plan has been reviewed:

```bash
npm run invitation:import -- --apply
```

The import script only writes `identity_invitations`; it does not modify legacy
Redis, deduct quota, send email, create users or write `invitation_record`.

## Dev Native Invitation Management Test

Enable only after invitation diagnostics and import dry-run are reviewed:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_INVITATION_ENABLED=true
IDENTITY_ACCOUNT_INVITATION_MANAGEMENT_NATIVE_ENABLED=true
IDENTITY_ACCOUNT_INVITATION_CHECK_NATIVE_ENABLED=true
IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED=true
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
IDENTITY_INVITATION_REDIS_URL=redis://10.206.16.15:6379/0
IDENTITY_DB_HOST=10.206.0.14
IDENTITY_DB_NAME=xrugc_identity_dev
IDENTITY_DB_USER=identity_dev
IDENTITY_DB_PASSWORD=...
```

Native invitation management covers:

- `GET /v1/plugin-user/invitations`
- `POST /v1/plugin-user/create-invitation`
- `POST /v1/plugin-user/delete-invitation`
- `GET /v1/plugin-user/check-invitation`
- `GET /v1/plugin-user/invitation-records`

It keeps these public registration paths on legacy/proxy:

- `POST /v1/plugin-user/register-send-code`
- `POST /v1/plugin-user/register`

Expected safety behavior:

- `invitations` reads legacy Redis and returns the old array shape.
- `create-invitation` writes `identity_invitations` and then legacy Redis.
- `delete-invitation` marks `identity_invitations` deleted and deletes legacy Redis.
- Elevated roles only: `root`, `admin`, `manager`.
- `check-invitation` is public readonly, reads identity DB, and falls back to
  legacy/proxy if identity DB and legacy Redis disagree.
- `invitation-records` is management-only readonly, reads legacy MySQL
  `invitation_record` joined with `user`, and returns the old snake_case array.
  It does not change quota, Redis, identity DB, users or registration state.

## Gray Order

1. Deploy identity-service with all account lifecycle flags disabled.
2. Confirm `/health` and `/internal/account-lifecycle/readiness`.
3. Enable one identity-service scope in dev with `legacy-proxy`.
4. Confirm the old API status code and body are unchanged.
5. Enable the matching main backend scope with fallback on.
6. Test internal accounts only.
7. Observe errors and latency for one release window.
8. Write a native sub-spec for that scope before replacing proxy behavior.
9. For register native, enable only `/v1/auth/register` and
   `/v1/wechat/register`; keep invitation registration on legacy.
10. For password native, enable only `/v1/password/change`; keep reset/code on
    legacy proxy.
11. Enable password reset native only after mail webhook delivery has been
    tested with internal accounts.
12. Enable email verification native for basic binding first.
13. Enable email change native only after basic binding and mail webhook tests
    are green; it can be disabled independently.
14. Enable invitation records native only after the legacy readonly MySQL
    account can read `invitation_record` and `user`; it can be disabled
    independently.
15. Do not enable native invitation registration before Redis invite data,
    identity DB invite data, quota ledger and legacy `invitation_record` are
    reconciled and dual-write has been tested.

## Main Backend Flags

The main backend remains legacy by default:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_PROVIDER=legacy
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=false
IDENTITY_ACCOUNT_LIFECYCLE_FALLBACK=true
```

To proxy only registration:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_PROVIDER=identity
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_REGISTER_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_ENABLED=false
IDENTITY_ACCOUNT_EMAIL_ENABLED=false
IDENTITY_ACCOUNT_INVITATION_ENABLED=false
```

## Rollback

- Turn off the affected scope first.
- If needed, set `IDENTITY_ACCOUNT_LIFECYCLE_PROVIDER=legacy` on the main backend.
- If needed, set `IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=false` on identity-service.
- No database rollback is required for the proxy bridge.
- For native register, successful user creation is a real legacy-compatible
  registration. Do not delete users as routine rollback; disable the flag and
  handle accidental test accounts manually.

## Remediation

| Problem | Action |
|---|---|
| Proxy loop | Confirm `X-Identity-Lifecycle-Proxy` reaches the main backend and the legacy base URL points to a legacy provider backend. |
| Legacy backend unavailable | Disable the scope or keep backend fallback enabled. |
| Native register cannot write old user data | Disable `IDENTITY_ACCOUNT_REGISTER_ENABLED`, confirm `LEGACY_WRITE_DB_*`, and retry only after readiness is green. |
| Native register issued user but frontend failed after token | Keep the created user; retry login through normal auth and inspect identity refresh session. |
| User retries the same register request | Confirm `account_lifecycle_operations` has a completed operation; identity-service should issue a new token without creating a second user. |
| Native password change fails for valid user | Disable `IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED`; confirm identity token issuer/audience and `LEGACY_WRITE_DB_*`. |
| User retries the same password change | Confirm `account_lifecycle_operations` has completed `password.change`; identity-service should return success without rewriting the password. |
| Native password reset email is not delivered | Disable `IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED`; confirm webhook logs and keep legacy reset enabled. |
| User retries the same password reset | Confirm `account_lifecycle_operations` has completed `password.reset`; identity-service should return success without rewriting again. |
| Legacy refresh sessions remain after native password change/reset | Confirm `IDENTITY_LEGACY_SESSION_REVOKE_ENABLED`, revoke URL, internal token, and main backend route `/v1/internal-identity/revoke-sessions`; disable the compensation flag if it is noisy. |
| Native email verification email is not delivered | Disable `IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED`; confirm webhook logs and keep legacy EmailService enabled. |
| User cannot change an already verified email | Disable `IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED`; confirm current-email code, change token TTL, webhook logs and `LEGACY_WRITE_DB_*`. |
| User cannot unbind a verified email | Disable `IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED`; confirm the frontend sent the current-email 6-digit code and the challenge was not consumed. |
| Email code failure | Disable email native or email scope and use legacy EmailService. |
| Password reset failure | Keep password scope on legacy until native reset has transaction rollback. |
| Invitation quota mismatch | Do not enable native invitation until `invitation_quota_ledger` repair steps are tested. |
