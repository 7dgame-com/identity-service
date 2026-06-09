# Local Smoke Runbook

## Standalone

```bash
npm install
npm test
npm run build
npm run dev
```

In another terminal:

```bash
npm run smoke
curl http://localhost:8086/health
curl http://localhost:8086/jwks.json
```

## Phase 4 Token Issuance Smoke

Token issuance is disabled by default. For local-only validation, provide a test
ES256 private key and enable the feature flag:

```bash
IDENTITY_TOKEN_ISSUANCE_ENABLED=true \
IDENTITY_JWT_PRIVATE_KEY_FILE=/path/to/local-test-ec-private-key.pem \
npm run dev
```

Then verify:

```bash
curl -X POST http://localhost:8086/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<legacy-user>","password":"<legacy-password>"}'
```

Expected result:

- response contains `token.accessToken`, `token.refreshToken`, `token.expires`
  and `token.tokenType=Bearer`;
- `GET /jwks.json` returns a public key with the configured `kid`;
- `POST /v1/auth/refresh` rotates the refresh token;
- replaying the previous refresh token returns 401;
- `POST /v1/auth/logout` is idempotent.

## Docker Compose

```bash
docker compose --profile identity up --build
curl http://localhost:8086/health
```

## Legacy DB Readonly Check

Use a readonly MySQL account before connecting to shared or production data.

```sql
CREATE USER 'identity_readonly'@'%' IDENTIFIED BY '<password>';
GRANT SELECT ON bujiaban.* TO 'identity_readonly'@'%';
```

Then set:

```bash
LEGACY_DB_USER=identity_readonly
LEGACY_DB_PASSWORD=<password>
```
