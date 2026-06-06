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

