# XR UGC Identity Service

This repository is the independent identity-service used by the XR UGC platform migration. It starts in readonly mode and can read legacy users, roles and organizations for comparison. Phase 4 adds optional token issuance, but it remains disabled by default and must be explicitly enabled for gray rollout.

## Local Start

```bash
npm install
npm test
npm run build
npm run dev
```

Health check:

```bash
curl http://localhost:8086/health
```

Docker:

```bash
docker compose --profile identity up --build
```

## Branches and CI/CD

This repository follows the main frontend branch model:

- `develop`: development image tag.
- `main`: stable image tag.
- `publish`: release image tag plus `latest`.

GitHub Actions runs `npm ci`, `npm audit`, `npm test`, `npm run build`, and Docker Compose config validation on `main`, `develop`, and `publish`. Pushes to those branches also build and push the Docker image:

```text
hkccr.ccs.tencentyun.com/gdgeek/identity-service:<branch>
hkccr.ccs.tencentyun.com/gdgeek/identity-service:latest  # publish only
```

Docker publishing uses the existing 7dgame organization registry secrets:
`TENCENT_REGISTRY_USER` or `TENCENT_REGISTRY_USERNAME`, and `TENCENT_REGISTRY_PASSWORD`.

## IAM Engine Boundary

Keycloak is the default IAM engine behind identity-service. Product code must treat
identity-service as the stable contract and must not bind directly to Keycloak.

- Frontends, backends, plugins and future content services use identity-service APIs, SDKs, OpenAPI, JWKS or published OIDC client configuration.
- Business systems must not call the Keycloak Admin API directly.
- Business systems must not modify Keycloak database tables or schema.
- MRPP users, organizations, roles, invitations and plugin permissions belong to the identity-adapter domain model.
- Keycloak owns protocol-level identity concerns: OIDC/OAuth2, clients, sessions, JWKS, MFA and the minimal user mapping needed for those flows.
- If another IAM engine is selected later, replace the identity-service IAM provider adapter instead of changing every consumer.

## Phase 3 Safety Rules

- Keep `IDENTITY_READONLY_MODE=true`.
- Use a readonly MySQL account for `LEGACY_DB_USER` outside local development.
- Do not point production frontend or backend traffic to this service yet.
- Keycloak is deployed only as an empty realm placeholder in this phase.
- Legacy auth remains the source of truth until a later spec explicitly switches traffic.

## Phase 3.5 Login Audit

Login audit is optional and disabled by default. It records successful login
source events and per-user login stats in the identity database only. It does
not write the legacy business database, does not bill users, does not deduct
quota, and does not block login or content access.

Required runtime settings when enabling it:

```bash
IDENTITY_LOGIN_AUDIT_ENABLED=true
IDENTITY_INTERNAL_API_TOKEN=<internal-service-token>
IDENTITY_DB_HOST=identity-mysql
IDENTITY_DB_NAME=xrugc_identity
IDENTITY_DB_USER=identity
IDENTITY_DB_PASSWORD=<identity-db-password>
```

Internal endpoints:

- `POST /internal/login-events`
- `GET /internal/login-audit/users/:legacyUserId`

These endpoints are intended for internal service-to-service calls only and
must not be exposed by the public Traefik/Nginx route.

## Phase 4 Token Issuance

Token issuance is optional and disabled by default. When enabled, identity-adapter
can authenticate legacy username/password, issue ES256 access tokens, rotate
refresh tokens in the identity database, and revoke sessions on logout.

Required runtime settings when enabling it:

```bash
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
IDENTITY_JWT_PRIVATE_KEY_FILE=/run/secrets/identity-jwt-key.pem
IDENTITY_JWT_KEY_ID=identity-stage4
IDENTITY_JWT_ISSUER=identity-service
IDENTITY_JWT_AUDIENCE=xrugc-api
IDENTITY_DB_HOST=identity-mysql
IDENTITY_DB_NAME=xrugc_identity
IDENTITY_DB_USER=identity
IDENTITY_DB_PASSWORD=<identity-db-password>
```

Public gray endpoints:

- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`
- `GET /jwks.json`

Safety rules:

- Keep `IDENTITY_TOKEN_ISSUANCE_ENABLED=false` unless the backend and frontend
  gray switches are ready.
- Main backend must default to `AUTH_PROVIDER=legacy`.
- Main frontend must default to `VITE_AUTH_PROVIDER=legacy`.
- `/api-auth` must not be captured by a broader `/api` reverse proxy route.
- Phase 4 does not migrate registration, password reset, email, invitations, or billing.

## Phase 5 Account Lifecycle

Account lifecycle migration is optional and disabled by default. Phase 5 starts
with a compatibility layer: identity-adapter can expose the old account API
paths and, when explicitly enabled, forward them to the legacy backend in
`legacy-proxy` mode. This verifies routing and response compatibility before
native register, password, email and invitation implementations replace the
proxy one scope at a time.

Required runtime settings for the compatibility bridge:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=legacy-proxy
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_REGISTER_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_ENABLED=false
IDENTITY_ACCOUNT_EMAIL_ENABLED=false
IDENTITY_ACCOUNT_INVITATION_ENABLED=false
```

Native registration is the first native sub-spec. It remains disabled unless
all register gates are enabled and a dedicated legacy write user is configured:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_REGISTER_ENABLED=true
IDENTITY_TOKEN_ISSUANCE_ENABLED=true
LEGACY_WRITE_DB_HOST=10.206.0.14
LEGACY_WRITE_DB_PORT=3306
LEGACY_WRITE_DB_NAME=bujiaban_development
LEGACY_WRITE_DB_USER=identity_writer
LEGACY_WRITE_DB_PASSWORD=...
```

Native register currently covers:

- `POST /v1/auth/register`
- `POST /v1/wechat/register`

It writes legacy-compatible `user`, `user_info`, `auth_assignment` and
`wechat.user_id` data in a transaction, then issues the phase-4 identity token
shape. `account_lifecycle_operations` records native register operations so the
same register request can be retried without creating duplicate legacy users.
Invitation register, password, email and invitation management remain separate
native specs.

Native password change is the first password sub-spec. It only covers
authenticated `POST /v1/password/change`; reset-code, verify-code and reset
remain on legacy/proxy until their own safety spec is implemented:

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

Native password change verifies the identity access token, checks the old
password, requires verified email, applies the same password policy, writes the
legacy password hash, records `account_lifecycle_operations` for idempotent
retry, and revokes identity refresh sessions.

Native password reset is a separate safety gate. It stores reset challenges in
identity DB and sends codes only through an explicitly configured email webhook:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_PASSWORD_ENABLED=true
IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_WEBHOOK_TOKEN=...
IDENTITY_PASSWORD_RESET_CODE_HASH_SALT=...
```

Native password reset covers:

- `POST /v1/password/request-reset`
- `POST /v1/password/verify-code`
- `POST /v1/password/reset`

It enforces a 6-digit code, hashed code storage, 15 minute TTL, 60 second send
rate limit, 5 failed attempts before lock, verified-email requirement, reset
operation idempotency, legacy password hash update, and identity refresh
session revocation.

Optional legacy refresh-session compensation can ask the main backend to revoke
its Yii Redis `RefreshToken` records after native password change/reset
succeeds. It is disabled by default and failure does not fail the user-facing
password operation:

```bash
IDENTITY_LEGACY_SESSION_REVOKE_ENABLED=true
IDENTITY_LEGACY_SESSION_REVOKE_URL=http://backend-api/v1/internal-identity/revoke-sessions
IDENTITY_LEGACY_SESSION_REVOKE_TOKEN=<internal-service-token>
IDENTITY_LEGACY_SESSION_REVOKE_TIMEOUT_MS=800
```

The main backend endpoint requires `X-Identity-Internal-Token` and only calls
`SessionService::revokeUserSessions($legacyUserId)`.

Native email verification is a separate safety gate. It covers only basic
email status, sending a new email verification code, verifying the code and
binding the email, plus cooldown lookup:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_EMAIL_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_WEBHOOK_TOKEN=...
IDENTITY_EMAIL_CODE_HASH_SALT=...
```

Native email verification covers:

- `GET /v1/email/status`
- `POST /v1/email/send-verification`
- `POST /v1/email/verify`
- `GET /v1/email/cooldown`

It stores hashed email verification challenges in identity DB, writes the
legacy `user.email` and `user.email_verified_at` fields after successful
verification.

Verified-email change and unbind are a separate safety gate. They remain
disabled unless the basic email native gate and the change native gate are both
enabled:

```bash
IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=true
IDENTITY_ACCOUNT_LIFECYCLE_MODE=native
IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL=http://legacy-backend-api
IDENTITY_ACCOUNT_EMAIL_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=true
IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED=true
IDENTITY_EMAIL_WEBHOOK_URL=https://mail.internal/send
IDENTITY_EMAIL_CHANGE_TOKEN_TTL_SECONDS=600
```

Native email change covers:

- `POST /v1/email/send-change-confirmation`
- `POST /v1/email/verify-change-confirmation`
- `POST /v1/email/verify` with `change_token`
- `POST /v1/email/unbind`

It sends the current-email confirmation code through the existing email
webhook, stores hashed change tokens in identity DB, requires `change_token`
before binding a different verified email, and lets the frontend unbind a
verified email with the current-email 6-digit code. The change gate can be
disabled independently to return these paths to legacy/proxy.

Invitation migration currently exposes only an internal readonly diagnostics
endpoint. It does not create invitations, delete invitations, send registration
codes, deduct quota, or register users:

```bash
IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED=true
IDENTITY_INTERNAL_API_TOKEN=...
IDENTITY_INVITATION_REDIS_URL=redis://10.206.16.15:6379/0
```

Internal endpoint:

- `GET /internal/account-lifecycle/invitations/diagnostics`

Use it to reconcile legacy Redis `invite:*` data and legacy MySQL
`invitation_record` counts before any invitation dual-write or native
registration rollout.

After reconciliation, the migration script can dry-run or import legacy Redis
invites into identity DB:

```bash
npm run invitation:import -- --dry-run
npm run invitation:import -- --apply
```

The default mode is dry-run. `--apply` only writes `identity_invitations`; it
does not modify legacy Redis, deduct quota, send email, register users or write
legacy `invitation_record`.

Invitation management native is the next safe step after import review. It only
covers management paths and dual-writes identity DB plus legacy Redis. The
public invitation check can also be enabled as readonly native:

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
```

Native invitation management covers:

- `GET /v1/plugin-user/invitations`
- `POST /v1/plugin-user/create-invitation`
- `POST /v1/plugin-user/delete-invitation`
- `GET /v1/plugin-user/check-invitation`
- `GET /v1/plugin-user/invitation-records`

It does not cover public invitation registration:

- `POST /v1/plugin-user/register-send-code`
- `POST /v1/plugin-user/register`

Those public registration paths remain legacy/proxy.

`check-invitation` reads identity DB and, when legacy Redis is configured,
compares the result with Redis. If they differ, identity-service falls back to
legacy/proxy.

`invitation-records` is management-only and readonly. It reads legacy MySQL
`invitation_record` joined with `user` and keeps the old snake_case response
shape. It does not modify Redis, identity DB, quota or registration data.

Readiness endpoint:

- `GET /internal/account-lifecycle/readiness`

Prepared compatibility endpoints:

- `POST /v1/auth/register`
- `POST /v1/wechat/register`
- `POST /v1/password/request-reset`
- `POST /v1/password/verify-code`
- `POST /v1/password/reset`
- `POST /v1/password/change`
- `GET /v1/email/status`
- `POST /v1/email/send-verification`
- `POST /v1/email/verify`
- `POST /v1/email/send-change-confirmation`
- `POST /v1/email/verify-change-confirmation`
- `POST /v1/email/unbind`
- `GET /v1/email/cooldown`
- `GET /v1/plugin-user/invitations`
- `POST /v1/plugin-user/create-invitation`
- `POST /v1/plugin-user/delete-invitation`
- `GET /v1/plugin-user/check-invitation`
- `GET /v1/plugin-user/invitation-records`
- `POST /v1/plugin-user/register-send-code`
- `POST /v1/plugin-user/register`

Safety rules:

- Keep `IDENTITY_ACCOUNT_LIFECYCLE_ENABLED=false` unless a scoped gray test is
  running.
- Enable only one scope per rollout window.
- Use a legacy backend URL that will not proxy back into identity-service.
- The proxy adds `X-Identity-Lifecycle-Proxy: 1`; the main backend must use
  that marker to avoid proxy loops before enabling backend lifecycle provider.
- Native register must use `LEGACY_WRITE_DB_*`; do not grant write permission
  to the read-only `LEGACY_DB_*` account.
- Native register does not send email, consume Redis verification codes or
  deduct invitation quota.
- Native password change/reset revoke identity refresh sessions. Optional
  legacy session compensation can also revoke the main backend Yii Redis
  refresh sessions through the internal backend endpoint.
- Native password reset uses identity DB challenges and an email webhook. Keep
  the webhook empty unless reset native is being explicitly gray-tested.
- Native email verification uses its own identity DB challenge table and the
  same email webhook. Keep `IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED=false`
  unless basic email binding is being explicitly gray-tested.
- Invitation diagnostics is internal and readonly. Keep
  `IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED=false` unless running a
  migration audit, and never expose `/internal/*` through public Traefik routes.
- Invitation management native must only be enabled after Redis-to-identity
  import dry-run has been reviewed. It still uses legacy Redis as the public
  compatibility source and keeps invitation registration on legacy/proxy.
- Invitation records native is readonly and management-only. Enable
  `IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED=true` only after the
  legacy readonly MySQL account can read `invitation_record` and `user`.
- `account_lifecycle_operations` and `invitation_quota_ledger` are created as
  safety tables for later native specs.

## OpenTelemetry

Telemetry is disabled by default and does not change local or development
runtime behavior. To export phase-3 request spans, configure an OTLP HTTP
collector endpoint:

```bash
OTEL_SERVICE_NAME=identity-adapter
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
```

`OTEL_EXPORTER_OTLP_ENDPOINT` is normalized to `/v1/traces`; use
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` when a provider requires an explicit trace
endpoint. Optional headers can be supplied with
`OTEL_EXPORTER_OTLP_HEADERS` or `OTEL_EXPORTER_OTLP_TRACES_HEADERS`.
