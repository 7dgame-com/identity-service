# XR UGC Identity Service

This repository is the independent identity-service used by the XR UGC platform migration. Phase 3 runs it in readonly mode only: it can read legacy users, roles and organizations for comparison, but it does not issue tokens or write the legacy platform database.

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
