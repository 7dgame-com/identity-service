# Identity-Service Rollback Runbook

Phase 3 and phase 4 are optional. Rollback should not touch legacy user data.

## Phase 4 Immediate Rollback

- Set main backend `AUTH_PROVIDER=legacy`.
- Set main frontend `VITE_AUTH_PROVIDER=legacy` or remove runtime `AUTH_PROVIDER=identity`.
- Set identity-service `IDENTITY_TOKEN_ISSUANCE_ENABLED=false`.
- Recreate affected containers so the environment switches take effect.
- Keep `IDENTITY_AUTH_LEGACY_REFRESH_FALLBACK=true` during gray rollback so
  pre-cutover legacy refresh tokens can still be consumed.

## Stop Runtime

```bash
docker compose --profile identity down
```

If running from the super project:

```bash
cd driver
docker compose -f docker-compose.yml -f docker-compose.identity.yml --profile identity down
```

## Close Routes

- Set `IDENTITY_EXPOSE_API_AUTH_ROUTE=false`.
- Remove the `/api-auth` Nginx route if it was enabled.
- If `/api-auth` was exposed through Traefik, make sure it is not shadowed by a
  broader `/api` route. Use ``Path(`/api`) || PathPrefix(`/api/`)`` for main API
  and ``Path(`/api-auth`) || PathPrefix(`/api-auth/`)`` for auth API.
- Keep legacy `/v1/auth/*` routes unchanged.

## Revert Submodule Pointer

```bash
git checkout <previous-release> -- services/identity-service .gitmodules
git submodule update --init --recursive services/identity-service
```

## Data Handling

- Do not drop or alter the legacy platform database.
- Keycloak and identity databases contain no source-of-truth user data in phase 3.
- Phase 4 identity refresh sessions may be retained for audit or cleared after
  all traffic has returned to legacy auth.
