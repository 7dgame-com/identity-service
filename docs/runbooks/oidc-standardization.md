# OIDC Standardization Runbook

This runbook covers stage 8. Stage 8 adds OIDC/OAuth2 standard surfaces while
keeping legacy authentication available and keeping IAM writes disabled.

## Safety Defaults

Keep these flags in develop and production until an explicit gray step says
otherwise:

```env
IDENTITY_OIDC_ENABLED=false
IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED=false
IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED=false
IDENTITY_OIDC_LOGOUT_ENDPOINT_ENABLED=false
IDENTITY_OIDC_REQUIRE_PKCE=true

IDENTITY_IAM_MODE=readonly
IDENTITY_IAM_PROFILE_WRITE_MODE=disabled
IDENTITY_IAM_ROLE_WRITE_MODE=disabled
IDENTITY_IAM_ORG_WRITE_MODE=disabled
IDENTITY_IAM_PLUGIN_USER_WRITE_MODE=disabled
IDENTITY_USAGE_BILLING_DRY_RUN=true
```

These settings make discovery and readiness testable without enabling
authorization-code traffic.

## Authorization Code + PKCE Gray Mode

Only enable active OIDC endpoints for an allowlisted test client after
discovery/readiness and legacy login regression are green:

```env
IDENTITY_OIDC_ENABLED=true
IDENTITY_OIDC_ISSUER=https://identity.xrteeth.com
IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED=true
IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED=true
IDENTITY_OIDC_LOGOUT_ENDPOINT_ENABLED=true
IDENTITY_OIDC_REQUIRE_PKCE=true
IDENTITY_OIDC_AUTHORIZATION_CODE_TTL_SECONDS=300
IDENTITY_OIDC_CLIENTS_JSON=[{"clientId":"xrugc-web-test","type":"public","enabled":true,"redirectUris":["https://dev.xrugc.com/oidc/callback"],"postLogoutRedirectUris":["https://dev.xrugc.com/logout/callback"],"scopes":["openid","profile","email","roles","organization","offline_access"],"requirePkce":true}]
```

Stage 8 authorization is a compatibility bridge: `/authorize` requires an
existing identity-service Bearer token and then redirects with an authorization
code. This prevents the service from exposing a half-finished login UI while
still validating standard authorization-code + PKCE mechanics.

The authorization code is stored in Identity DB as a hash, has a short TTL, and
is single-use. With shared Identity DB, a code issued by one identity node can be
exchanged by the other node.

## Public Checks

```sh
curl -sS https://identity.xrteeth.com/health
curl -sS https://identity.xrteeth.com/.well-known/openid-configuration
curl -sS -o /dev/null -w '%{http_code}\n' https://identity.xrteeth.com/internal/oidc/readiness
```

Expected:

- `/health` returns `ok`.
- discovery returns `xrugc_stage=identity-oidc-standardization`.
- `/internal/oidc/readiness` returns `404` from the public route.

Repeat for `https://identity.tmrpp.com`.

## Internal Readiness

Run inside the `identity-adapter` container:

```sh
TOKEN="${IDENTITY_IAM_INTERNAL_API_TOKEN:-$IDENTITY_INTERNAL_API_TOKEN}"
wget -qO- --header="X-Identity-Internal-Token: $TOKEN" \
  http://127.0.0.1:8086/internal/oidc/readiness
```

Expected:

- `status=ok`
- `capability=oidc`
- authorization/token/logout endpoints match the gray flags
- `stores.authorizationCode=configured` before enabling active OIDC endpoints
- no client secrets are printed

## Token Smoke

Use an existing identity JWT from `/v1/auth/login`, then run an OIDC bridge
authorize request with a PKCE S256 challenge. For browser XHR bridge tests, use
`response_mode=json`; normal OIDC navigation can omit it and receives a `302`.

```sh
curl -i -H "Authorization: Bearer <identity-access-token>" \
  "https://identity.xrteeth.com/authorize?response_type=code&response_mode=json&client_id=xrugc-web-test&redirect_uri=https%3A%2F%2Fdev.xrugc.com%2Foidc%2Fcallback&scope=openid%20profile%20email&state=smoke&code_challenge=<s256-challenge>&code_challenge_method=S256"

curl -sS -X POST https://identity.xrteeth.com/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"authorization_code","client_id":"xrugc-web-test","redirect_uri":"https://dev.xrugc.com/oidc/callback","code":"<code>","code_verifier":"<verifier>"}'
```

Expected token response contains `access_token`, `id_token`, `token_type=Bearer`
and `expires_in`. `refresh_token` is returned only when `offline_access` is in
the requested scope.

## Main Frontend Gray Switches

Keep the frontend bridge disabled until the identity-service test client is
ready:

```env
AUTH_PROVIDER=identity
VITE_AUTH_PROVIDER=identity
VITE_APP_AUTH_API=/api-auth
VITE_IDENTITY_OIDC_BRIDGE_ENABLED=false
VITE_IDENTITY_OIDC_CLIENT_ID=xrugc-web-test
VITE_IDENTITY_OIDC_REDIRECT_URI=https://dev.xrugc.com/oidc/callback
VITE_IDENTITY_OIDC_SCOPE=openid profile email offline_access
```

When `VITE_IDENTITY_OIDC_BRIDGE_ENABLED=true`, the main frontend first performs
the existing identity `/v1/auth/login`, then silently tries
`/authorize?response_mode=json` + `/token`. If the bridge fails, it keeps the
original identity login token and the user remains logged in.

## Logout Smoke

Only configured `postLogoutRedirectUris` can be used:

```sh
curl -i "https://identity.xrteeth.com/logout?client_id=xrugc-web-test&post_logout_redirect_uri=https%3A%2F%2Fdev.xrugc.com%2Flogout%2Fcallback&state=logout-smoke"
```

Expected: `302` to the allowlisted URI. An unknown URI must return `400`.

## Admin MFA And Break Glass

Stage 8 exposes MFA readiness but does not make identity-service the Keycloak
admin console owner. Keep at least one emergency admin path outside normal OIDC
traffic:

- keep `IDENTITY_OIDC_ADMIN_MFA_REQUIRED=true` only after the emergency admin is
  tested;
- keep one Keycloak/Portainer break-glass admin credential in the existing
  operations password vault;
- if admin MFA locks operators out, disable the affected OIDC admin client or
  set `IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED=false` and use the
  break-glass admin path to reset MFA;
- do not change IAM write modes or `IDENTITY_IAM_MODE` during MFA recovery.

## Rollback

Rollback is configuration-only:

```env
IDENTITY_OIDC_ENABLED=false
IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED=false
IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED=false
IDENTITY_OIDC_LOGOUT_ENDPOINT_ENABLED=false
```

Do not change legacy `/v1/auth/*`, account lifecycle or IAM write modes during
an OIDC rollback.
