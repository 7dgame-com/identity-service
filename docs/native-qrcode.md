# Independent QR compatibility

These routes are active only with `IDENTITY_DATA_SOURCE=identity`. They retain the existing browser and Unity protocol; an unavailable private store/provider never selects the old account writer.

Apply `deploy/mysql/identity-qrcode-schema.sql` after the account/runtime and WeChat OAuth schemas. The native QR service also uses the existing registration, token issuance and session services. Set `IDENTITY_WECHAT_PROVIDER_BASE_URL` to the internal auth-service origin. Identity and auth-service must agree on `IDENTITY_TOKEN_ISSUANCE_INTERNAL_API_TOKEN` / `AUTH_IDENTITY_API_TOKEN`.

| Route | Behavior |
| --- | --- |
| `GET /v1/tools/user-linked` | Authenticated, authorized 60 second device code |
| `GET /v1/tools/user-linked/status?key=` | Owner-only active/expired status |
| `POST /v1/auth/refresh` with `refreshToken=web_<code>` or a QR URL | AuthController delegates to `redeemLoginCode`; every device receives a separate session |
| `GET /v1/wechat/qrcode` | Existing six day temporary WeChat scene and QR image URL |
| `GET /v1/wechat/refresh?token=` | `pending`, `signin` with scene, or `signup` with the registration token |
| `POST /v1/wechat/login` | Rechecks the current linked Identity account and issues a session |
| `POST /v1/wechat/register` | Confirms a live scan token, then uses existing transactional registration and binding |
| `POST /internal/wechat-provider/confirm-scan` | Internal assertion accepted only after auth-service verifies the WeChat callback signature |

The two WeChat GET routes and registration route are delegated by the existing AccountLifecycleController, avoiding duplicate route registrations. Auth-service owns provider protocol/signature verification and exposes internal `qrcode` and `profile` operations; its independent public GET routes proxy these Identity routes.

Login codes persist only SHA-256 digest, user ID and issue/expiry times. Multiple codes and multiple device exchanges may coexist during the fixed 60 second window. Redemption does not consume the code or reuse a refresh token. Per-user issuance is serialized with the account row and retains the default five requests per minute limit. Session issuance rechecks enabled account status.

Scenes persist a digest, provider app/open ID, confirmed user ID and profile. A scene cannot be rebound to another provider subject. The provider profile's app and open ID must match the callback assertion. Unbound scans use the existing private WeChat registration token, while the scene stores only its digest and checks expiry before registration. Account creation and the WeChat binding are committed in the same existing registration transaction.

Expired login-code and scene rows can be removed by retention maintenance after their expiry; expiry is checked on reads independently of deletion. Do not log codes, scene tokens or signup tokens. No QR table stores plaintext refresh tokens.

`native-qrcode.spec.ts` covers protocol shape, expiry, disabled users, owner privacy, provider binding and internal authentication. The optional MySQL suite creates a random test database and drops it afterward:

```sh
IDENTITY_TEST_MYSQL=1 pnpm exec vitest run \
  apps/identity-adapter/test/native-qrcode.spec.ts \
  apps/identity-adapter/test/native-qrcode-mysql.spec.ts
```

Optional connection overrides are `IDENTITY_TEST_MYSQL_HOST`, `PORT`, `USER` and `PASSWORD`. Defaults are `127.0.0.1:13316`, `identity_test`, empty password. The suite requires permission to create/drop its own test database.

Pending QR scenes, legacy plaintext/hashed short-code stores and signup tokens created before cutover still require an explicit import/expiry plan. Old unversioned callback and Apple routes are separate readiness items. Keep independent HTTP readiness disabled until these and the full account/session compatibility checks pass.
