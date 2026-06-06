# Phase 3 Rollback Runbook

Phase 3 is readonly and optional. Rollback should not touch legacy user data.

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
- Keep legacy `/v1/auth/*` routes unchanged.

## Revert Submodule Pointer

```bash
git checkout <previous-release> -- services/identity-service .gitmodules
git submodule update --init --recursive services/identity-service
```

## Data Handling

- Do not drop or alter the legacy platform database.
- Keycloak and identity databases contain no source-of-truth user data in phase 3 and may be recreated if needed.

