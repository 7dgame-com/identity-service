import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { BadRequestException, Injectable, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import { IdentitySessionRepository } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import {
  InvalidAuthorizationCodeError,
  OidcAuthorizationCodeRepository
} from "./oidc-authorization-code.repository.js";
import { TokenIssuanceService } from "./token-issuance.service.js";

interface OidcClientConfig {
  clientId: string;
  enabled: boolean;
  type: "public" | "confidential";
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  requirePkce: boolean;
  adminMfaRequired: boolean;
  clientSecret: string | null;
}

interface AuthorizeRequest {
  responseType: "code";
  clientId: string;
  redirectUri: string;
  scope: string[];
  state: string | null;
  nonce: string | null;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  responseMode: "query" | "json";
}

interface TokenRequest {
  grantType: "authorization_code" | "refresh_token";
  clientId: string;
  clientSecret: string | null;
  code: string | null;
  redirectUri: string | null;
  codeVerifier: string | null;
  refreshToken: string | null;
}

interface OidcTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
}

interface OidcIssuerContext {
  host?: string;
  forwardedHost?: string;
}

@Injectable()
export class OidcService {
  private readonly config = loadConfig();

  constructor(
    private readonly codes: OidcAuthorizationCodeRepository,
    private readonly legacyReader: LegacyIdentityReader,
    private readonly sessions: IdentitySessionRepository,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly tokenIssuance: TokenIssuanceService
  ) {}

  discovery(context?: OidcIssuerContext) {
    const issuer = this.issuer(context);

    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks.json`,
      end_session_endpoint: `${issuer}/logout`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
      scopes_supported: ["openid", "profile", "email", "roles", "permissions", "organization", "offline_access"],
      claims_supported: [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "jti",
        "preferred_username",
        "email",
        "email_verified",
        "roles",
        "permissions",
        "organization"
      ],
      code_challenge_methods_supported: ["S256"],
      xrugc_stage: "identity-oidc-standardization",
      xrugc_response_modes_supported: ["query", "json"],
      xrugc_capabilities: {
        enabled: this.config.oidc.enabled,
        authorizationEndpoint: this.config.oidc.authorizationEndpointEnabled ? "enabled" : "disabled",
        tokenEndpoint: this.config.oidc.tokenEndpointEnabled ? "enabled" : "disabled",
        logoutEndpoint: this.config.oidc.logoutEndpointEnabled ? "enabled" : "disabled",
        pkceRequired: this.config.oidc.requirePkce,
        legacyAuthFallbackRequired: true,
        identityPrimaryCutoverAllowed: false
      }
    };
  }

  readiness(context?: OidcIssuerContext) {
    const clients = this.clients();
    const enabledClients = clients.filter((client) => client.enabled);
    const issuer = this.safeIssuerForReadiness(context);

    return {
      enabled: this.config.oidc.enabled,
      issuer,
      issuerMode: this.config.oidc.issuerMode,
      issuerScheme: this.config.oidc.issuerScheme,
      allowedIssuerHosts: this.allowedIssuerHosts(),
      endpoints: {
        discovery: "enabled",
        authorization: this.config.oidc.authorizationEndpointEnabled ? "enabled" : "disabled",
        token: this.config.oidc.tokenEndpointEnabled ? "enabled" : "disabled",
        userinfo: "identity-token-only",
        jwks: "enabled",
        logout: this.config.oidc.logoutEndpointEnabled ? "enabled" : "disabled"
      },
      clients: {
        configured: clients.length,
        enabled: enabledClients.length,
        entries: clients.map((client) => ({
          clientId: client.clientId,
          enabled: client.enabled,
          type: client.type,
          redirectUriCount: client.redirectUris.length,
          postLogoutRedirectUriCount: client.postLogoutRedirectUris.length,
          scopes: client.scopes,
          requirePkce: client.requirePkce,
          adminMfaRequired: client.adminMfaRequired,
          clientSecretConfigured: client.type === "confidential" ? Boolean(client.clientSecret) : undefined
        }))
      },
      stores: {
        authorizationCode: this.codes.isConfigured() ? "configured" : "not_configured",
        ttlSeconds: this.config.oidc.authorizationCodeTtlSeconds
      },
      safety: {
        authorizationCodePkceRequired: this.config.oidc.requirePkce,
        legacyAuthFallbackRequired: true,
        identityPrimaryCutoverAllowed: false,
        accountLifecycleRemainsLegacyCompatible: true,
        adminMfaRequired: this.config.oidc.adminMfaRequired,
        adminClientsRequiringMfa: enabledClients.filter((client) => client.adminMfaRequired).map((client) => client.clientId)
      }
    };
  }

  assertInternalToken(token: string | undefined) {
    const expected = this.config.iam.internalToken ?? this.config.loginAudit.internalToken;
    if (!expected) {
      throw new ServiceUnavailableException({
        code: "OIDC_INTERNAL_TOKEN_REQUIRED",
        message: "Internal API token is required before reading OIDC readiness."
      });
    }
    if (token !== expected) {
      throw new UnauthorizedException({
        code: "OIDC_INTERNAL_TOKEN_INVALID",
        message: "Internal service token is invalid."
      });
    }
  }

  assertEndpointEnabled(endpoint: "authorization" | "token" | "logout") {
    const endpointEnabled =
      endpoint === "authorization"
        ? this.config.oidc.authorizationEndpointEnabled
        : endpoint === "token"
          ? this.config.oidc.tokenEndpointEnabled
          : this.config.oidc.logoutEndpointEnabled;

    if (!this.config.oidc.enabled || !endpointEnabled) {
      throw new ServiceUnavailableException({
        code: "OIDC_ENDPOINT_DISABLED",
        message: `OIDC ${endpoint} endpoint is disabled for safe staged rollout.`
      });
    }
  }

  async authorize(
    query: Record<string, unknown>,
    authorization: string | undefined
  ): Promise<{ responseMode: "query"; redirectUrl: string } | { responseMode: "json"; code: string; state: string | null; redirectUri: string }> {
    this.assertEndpointEnabled("authorization");
    const request = parseAuthorizeRequest(query);
    const client = this.requireClient(request.clientId);
    assertRedirectUri(client, request.redirectUri);
    const scope = assertScopes(client, request.scope);
    assertPkce(client, request.codeChallenge, request.codeChallengeMethod);

    const claims = this.verifyIdentityBearer(authorization);
    const user = await this.requireLegacyUser(claims.uid);
    if (!this.codes.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "OIDC_AUTHORIZATION_CODE_STORE_NOT_CONFIGURED",
        message: "Identity database is required before enabling OIDC authorization codes."
      });
    }

    const authTime = new Date();
    const issued = await this.codes.issue({
      clientId: client.clientId,
      redirectUri: request.redirectUri,
      legacyUserId: user.id,
      username: user.username,
      scope: scope.join(" "),
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: "S256",
      nonce: request.nonce,
      authTime,
      expiresAt: new Date(authTime.getTime() + this.config.oidc.authorizationCodeTtlSeconds * 1000)
    });

    if (request.responseMode === "json") {
      return {
        responseMode: "json",
        code: issued.code,
        state: request.state,
        redirectUri: request.redirectUri
      };
    }

    return {
      responseMode: "query",
      redirectUrl: appendQuery(request.redirectUri, {
        code: issued.code,
        state: request.state
      })
    };
  }

  async token(payload: unknown, authorization: string | undefined, context?: OidcIssuerContext): Promise<OidcTokenResponse> {
    this.assertEndpointEnabled("token");
    const request = parseTokenRequest(payload, authorization);
    const client = this.requireClient(request.clientId);
    assertClientAuthenticated(client, request.clientSecret);

    if (request.grantType === "refresh_token") {
      return this.refreshToken(request);
    }

    if (!request.code || !request.redirectUri || !request.codeVerifier) {
      throw invalidRequest("code, redirect_uri and code_verifier are required for authorization_code exchange.");
    }

    let code;
    try {
      code = await this.codes.consume({
        code: request.code,
        clientId: client.clientId,
        redirectUri: request.redirectUri
      });
    } catch (error) {
      if (error instanceof InvalidAuthorizationCodeError) {
        throw new BadRequestException({
          code: "INVALID_GRANT",
          message: "Authorization code is invalid, expired or already consumed."
        });
      }
      throw error;
    }

    if (!verifyPkceS256(request.codeVerifier, code.codeChallenge)) {
      throw new BadRequestException({
        code: "INVALID_GRANT",
        message: "PKCE code verifier is invalid."
      });
    }

    const user = await this.requireLegacyUser(code.legacyUserId);
    const scopes = code.scope.split(" ").filter(Boolean);
    const session = scopes.includes("offline_access") ? await this.issueRefreshSession(user) : null;
    const accessToken = this.jwtIssuer.issue(user, session?.sessionId ?? randomId());
    const idToken = this.jwtIssuer.issueOidcIdToken({
      user,
      issuer: this.issuer(context),
      audience: client.clientId,
      authTime: code.authTime,
      nonce: code.nonce,
      scope: scopes
    });

    return {
      access_token: accessToken.accessToken,
      token_type: "Bearer",
      expires_in: secondsUntil(accessToken.expiresAt),
      id_token: idToken.accessToken,
      refresh_token: session?.refreshToken,
      scope: code.scope
    };
  }

  async logout(payload: unknown): Promise<{ success: true; redirectUrl: string | null }> {
    this.assertEndpointEnabled("logout");
    const body = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as Record<string, unknown>) : {};
    const clientId = single(body.client_id);
    const postLogoutRedirectUri = single(body.post_logout_redirect_uri);
    const state = single(body.state);
    const refreshToken = single(body.refresh_token);

    if (refreshToken) {
      await this.tokenIssuance.logout({ refreshToken });
    }

    if (!postLogoutRedirectUri) {
      return { success: true, redirectUrl: null };
    }

    if (!clientId) {
      throw invalidRequest("client_id is required when post_logout_redirect_uri is provided.");
    }

    const client = this.requireClient(clientId);
    if (!client.postLogoutRedirectUris.includes(postLogoutRedirectUri)) {
      throw new BadRequestException({
        code: "INVALID_POST_LOGOUT_REDIRECT_URI",
        message: "post_logout_redirect_uri is not allowed for this client."
      });
    }

    return {
      success: true,
      redirectUrl: appendQuery(postLogoutRedirectUri, { state: state || null })
    };
  }

  private issuer(context?: OidcIssuerContext) {
    if (this.config.oidc.issuerMode === "request-host") {
      const host = requestHost(context);
      const allowedHosts = this.allowedIssuerHosts();
      if (!host || !allowedHosts.includes(host)) {
        throw new BadRequestException({
          code: "OIDC_ISSUER_HOST_NOT_ALLOWED",
          message: "OIDC issuer host is not allowlisted for this deployment."
        });
      }
      return `${this.config.oidc.issuerScheme}://${host}`;
    }

    return trimTrailingSlash(this.config.oidc.issuer ?? this.config.jwt.issuer);
  }

  private safeIssuerForReadiness(context?: OidcIssuerContext) {
    try {
      return this.issuer(context);
    } catch {
      return this.config.oidc.issuerMode === "request-host"
        ? `${this.config.oidc.issuerScheme}://{request-host}`
        : trimTrailingSlash(this.config.oidc.issuer ?? this.config.jwt.issuer);
    }
  }

  private allowedIssuerHosts() {
    return this.config.oidc.allowedIssuerHosts
      .split(",")
      .map((host) => normalizeIssuerHost(host))
      .filter((host): host is string => Boolean(host));
  }

  private verifyIdentityBearer(authorization: string | undefined) {
    const token = bearerToken(authorization);
    if (!token) {
      throw new UnauthorizedException({
        code: "OIDC_LOGIN_REQUIRED",
        message: "An existing identity bearer token is required for staged OIDC authorization."
      });
    }

    try {
      return this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw new UnauthorizedException({
        code: "INVALID_ACCESS_TOKEN",
        message: "Identity bearer token is invalid for OIDC authorization."
      });
    }
  }

  private async refreshToken(request: TokenRequest): Promise<OidcTokenResponse> {
    if (!request.refreshToken) {
      throw invalidRequest("refresh_token is required for refresh_token grant.");
    }

    const refreshed = await this.tokenIssuance.refresh({ refreshToken: request.refreshToken });
    const expiresAt = new Date(refreshed.token.expires);

    return {
      access_token: refreshed.token.accessToken,
      token_type: "Bearer",
      expires_in: secondsUntil(expiresAt),
      refresh_token: refreshed.token.refreshToken
    };
  }

  private async requireLegacyUser(id: number): Promise<LegacyUserReadModel> {
    const user = await this.legacyReader.getUserById(id);
    if (!user) {
      throw new UnauthorizedException({
        code: "LEGACY_USER_NOT_FOUND",
        message: "Legacy user was not found."
      });
    }

    return user;
  }

  private async issueRefreshSession(user: LegacyUserReadModel) {
    if (!this.sessions.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is required before issuing OIDC refresh tokens."
      });
    }

    return this.sessions.issue({
      legacyUserId: user.id,
      username: user.username,
      sessionId: randomId(),
      expiresAt: new Date(Date.now() + this.config.tokenIssuance.refreshTokenTtlSeconds * 1000)
    });
  }

  private clients(): OidcClientConfig[] {
    try {
      const parsed = JSON.parse(this.config.oidc.clientsJson);
      if (!Array.isArray(parsed)) {
        return [];
      }

      return parsed.flatMap((entry): OidcClientConfig[] => {
        if (!entry || typeof entry !== "object") {
          return [];
        }
        const record = entry as Record<string, unknown>;
        const clientId = typeof record.clientId === "string" ? record.clientId.trim() : "";
        if (!clientId) {
          return [];
        }

        return [
          {
            clientId,
            enabled: record.enabled !== false,
            type: record.type === "confidential" ? "confidential" : "public",
            redirectUris: stringArray(record.redirectUris),
            postLogoutRedirectUris: stringArray(record.postLogoutRedirectUris),
            scopes: stringArray(record.scopes),
            requirePkce: record.requirePkce === false ? false : this.config.oidc.requirePkce,
            adminMfaRequired: record.adminMfaRequired === true || this.config.oidc.adminMfaRequired,
            clientSecret: clientSecret(record)
          }
        ];
      });
    } catch {
      return [];
    }
  }

  private requireClient(clientId: string): OidcClientConfig {
    const client = this.clients().find((entry) => entry.clientId === clientId);
    if (!client || !client.enabled) {
      throw new BadRequestException({
        code: "INVALID_CLIENT",
        message: "OIDC client is not configured or disabled."
      });
    }

    return client;
  }
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.trim() !== "") : [];
}

function parseAuthorizeRequest(query: Record<string, unknown>): AuthorizeRequest {
  const responseType = single(query.response_type);
  const clientId = single(query.client_id);
  const redirectUri = single(query.redirect_uri);
  const scope = parseScopes(single(query.scope));
  const state = single(query.state);
  const nonce = single(query.nonce);
  const codeChallenge = single(query.code_challenge);
  const codeChallengeMethod = single(query.code_challenge_method);
  const responseModeValue = single(query.response_mode);
  const responseMode = responseModeValue === "json" ? "json" : "query";

  if (responseType !== "code") {
    throw unsupportedResponseType();
  }
  if (!clientId || !redirectUri) {
    throw invalidRequest("client_id and redirect_uri are required.");
  }
  if (!scope.includes("openid")) {
    throw invalidScope("OIDC authorization requires the openid scope.");
  }
  if (!codeChallenge || codeChallengeMethod !== "S256") {
    throw invalidRequest("PKCE S256 code_challenge is required.");
  }

  return {
    responseType: "code",
    clientId,
    redirectUri,
    scope,
    state: state || null,
    nonce: nonce || null,
    codeChallenge,
    codeChallengeMethod: "S256",
    responseMode
  };
}

function parseTokenRequest(payload: unknown, authorization: string | undefined): TokenRequest {
  const body = payload && typeof payload === "object" && !Array.isArray(payload) ? (payload as Record<string, unknown>) : {};
  const basic = basicClientCredentials(authorization);
  const grantType = single(body.grant_type);
  if (grantType !== "authorization_code" && grantType !== "refresh_token") {
    throw unsupportedGrantType();
  }
  const clientId = basic?.clientId ?? single(body.client_id);
  if (!clientId) {
    throw invalidRequest("client_id is required.");
  }

  return {
    grantType,
    clientId,
    clientSecret: (basic?.clientSecret ?? single(body.client_secret)) || null,
    code: single(body.code) || null,
    redirectUri: single(body.redirect_uri) || null,
    codeVerifier: single(body.code_verifier) || null,
    refreshToken: single(body.refresh_token) || null
  };
}

function assertRedirectUri(client: OidcClientConfig, redirectUri: string): void {
  if (!client.redirectUris.includes(redirectUri)) {
    throw new BadRequestException({
      code: "INVALID_REDIRECT_URI",
      message: "redirect_uri is not allowed for this client."
    });
  }
}

function assertScopes(client: OidcClientConfig, requested: string[]): string[] {
  const unique = Array.from(new Set(requested));
  const invalid = unique.filter((scope) => !client.scopes.includes(scope));
  if (invalid.length > 0) {
    throw invalidScope(`Client is not allowed to request scope: ${invalid.join(", ")}.`);
  }

  return unique;
}

function assertPkce(client: OidcClientConfig, challenge: string, method: "S256"): void {
  if (!client.requirePkce) {
    return;
  }
  if (method !== "S256" || !isPkceValue(challenge)) {
    throw invalidRequest("PKCE S256 code_challenge is invalid.");
  }
}

function assertClientAuthenticated(client: OidcClientConfig, providedSecret: string | null): void {
  if (client.type === "public") {
    return;
  }
  if (!client.clientSecret || providedSecret !== client.clientSecret) {
    throw new UnauthorizedException({
      code: "INVALID_CLIENT_SECRET",
      message: "Confidential client authentication failed."
    });
  }
}

function verifyPkceS256(verifier: string, expectedChallenge: string): boolean {
  if (!isPkceValue(verifier)) {
    return false;
  }
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return timingSafeEqualString(challenge, expectedChallenge);
}

function isPkceValue(value: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }

  return timingSafeEqual(left, right);
}

function appendQuery(url: string, params: Record<string, string | null>): string {
  const parsed = new URL(url);
  for (const [key, value] of Object.entries(params)) {
    if (value) {
      parsed.searchParams.set(key, value);
    }
  }

  return parsed.toString();
}

function parseScopes(value: string): string[] {
  const scopes = value
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);

  return scopes.length > 0 ? scopes : ["openid"];
}

function single(value: unknown): string {
  if (Array.isArray(value)) {
    return single(value[0]);
  }
  return typeof value === "string" ? value.trim() : "";
}

function clientSecret(record: Record<string, unknown>): string | null {
  const direct = typeof record.clientSecret === "string" ? record.clientSecret.trim() : "";
  if (direct) {
    return direct;
  }

  const envName = typeof record.clientSecretEnv === "string" ? record.clientSecretEnv.trim() : "";
  const fromEnv = envName ? process.env[envName]?.trim() : "";

  return fromEnv || null;
}

function basicClientCredentials(authorization: string | undefined): { clientId: string; clientSecret: string } | null {
  if (!authorization?.startsWith("Basic ")) {
    return null;
  }
  try {
    const decoded = Buffer.from(authorization.slice("Basic ".length), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) {
      return null;
    }

    return {
      clientId: decodeURIComponent(decoded.slice(0, separator)),
      clientSecret: decodeURIComponent(decoded.slice(separator + 1))
    };
  } catch {
    return null;
  }
}

function bearerToken(value: string | undefined): string | null {
  if (!value?.startsWith("Bearer ")) {
    return null;
  }
  return value.slice("Bearer ".length).trim() || null;
}

function invalidRequest(message: string): BadRequestException {
  return new BadRequestException({
    code: "INVALID_REQUEST",
    message
  });
}

function invalidScope(message: string): BadRequestException {
  return new BadRequestException({
    code: "INVALID_SCOPE",
    message
  });
}

function unsupportedGrantType(): BadRequestException {
  return new BadRequestException({
    code: "UNSUPPORTED_GRANT_TYPE",
    message: "Only authorization_code and refresh_token grants are supported."
  });
}

function unsupportedResponseType(): BadRequestException {
  return new BadRequestException({
    code: "UNSUPPORTED_RESPONSE_TYPE",
    message: "Only response_type=code is supported."
  });
}

function requestHost(context: OidcIssuerContext | undefined): string | null {
  const raw = firstHeaderValue(context?.forwardedHost) || firstHeaderValue(context?.host);
  return normalizeIssuerHost(raw);
}

function firstHeaderValue(value: string | undefined): string {
  return value?.split(",")[0]?.trim() ?? "";
}

function normalizeIssuerHost(value: string | undefined): string | null {
  const raw = value?.trim().toLowerCase();
  if (!raw) {
    return null;
  }

  let host = raw;
  if (host.startsWith("http://") || host.startsWith("https://")) {
    try {
      host = new URL(host).host;
    } catch {
      return null;
    }
  }

  if (host.includes("/") || host.includes("@")) {
    return null;
  }

  return host.replace(/:\d+$/, "") || null;
}

function secondsUntil(value: Date): number {
  return Math.max(0, Math.floor((value.getTime() - Date.now()) / 1000));
}

function randomId(): string {
  return randomBytes(24).toString("base64url");
}
