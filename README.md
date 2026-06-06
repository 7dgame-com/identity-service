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

## Phase 3 Safety Rules

- Keep `IDENTITY_READONLY_MODE=true`.
- Use a readonly MySQL account for `LEGACY_DB_USER` outside local development.
- Do not point production frontend or backend traffic to this service yet.
- Keycloak is deployed only as an empty realm placeholder in this phase.
- Legacy auth remains the source of truth until a later spec explicitly switches traffic.

