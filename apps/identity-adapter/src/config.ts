import { z } from "zod";

const boolFromEnv = z
  .union([z.boolean(), z.string()])
  .optional()
  .transform((value) => {
    if (typeof value === "boolean") {
      return value;
    }
    if (typeof value === "string") {
      return ["1", "true", "yes", "on"].includes(value.toLowerCase());
    }
    return true;
  });

const numberFromEnv = z
  .union([z.number(), z.string()])
  .optional()
  .transform((value) => {
    if (typeof value === "number") {
      return value;
    }
    if (typeof value === "string" && value.trim() !== "") {
      return Number(value);
    }
    return undefined;
  });

const optionalStringFromEnv = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = value?.trim();
    return trimmed === "" ? undefined : trimmed;
  });

export const configSchema = z.object({
  nodeEnv: z.string().default("development"),
  port: numberFromEnv.default(8086),
  readonlyMode: boolFromEnv.default(true),
  jwksPublicKeysJson: z.string().default('{"keys":[]}'),
  legacyDb: z.object({
    host: z.string().optional(),
    port: numberFromEnv.default(3306),
    name: z.string().default("bujiaban"),
    user: z.string().optional(),
    password: z.string().optional()
  }),
  legacyWriteDb: z.object({
    host: z.string().optional(),
    port: numberFromEnv.default(3306),
    name: z.string().default("bujiaban"),
    user: z.string().optional(),
    password: z.string().optional()
  }),
  identityDb: z.object({
    host: z.string().optional(),
    port: numberFromEnv.default(3306),
    name: z.string().default("xrugc_identity"),
    user: z.string().optional(),
    password: z.string().optional()
  }),
  loginAudit: z.object({
    enabled: boolFromEnv.default(false),
    internalToken: optionalStringFromEnv,
    hashSalt: z.string().default("xrugc-login-audit-v1")
  }),
  usageBilling: z.object({
    shadowEnabled: boolFromEnv.default(false),
    dryRun: boolFromEnv.default(true),
    loginRule: z.string().default("successful-login-v1"),
    freeLoginQuota: numberFromEnv.default(0),
    subjectStrategy: z.enum(["user", "organization", "customer"]).default("user"),
    replayBatchSize: numberFromEnv.default(500),
    internalToken: optionalStringFromEnv
  }),
  iam: z.object({
    enabled: boolFromEnv.default(false),
    mode: z.enum(["disabled", "readonly", "shadow", "identity-primary"]).default("disabled"),
    fallbackEnabled: boolFromEnv.default(true),
    schemaAutoEnsureEnabled: boolFromEnv.default(false),
    reconciliationEnabled: boolFromEnv.default(false),
    reconciliationBatchSize: numberFromEnv.default(500),
    internalToken: optionalStringFromEnv,
    userViewEnabled: boolFromEnv.default(false),
    roleViewEnabled: boolFromEnv.default(false),
    permissionViewEnabled: boolFromEnv.default(false),
    organizationViewEnabled: boolFromEnv.default(false),
    pluginViewEnabled: boolFromEnv.default(false),
    profileWriteMode: z.enum(["disabled", "legacy-proxy", "dual-write", "identity-native"]).default("disabled"),
    roleWriteMode: z.enum(["disabled", "legacy-proxy", "dual-write", "identity-native"]).default("disabled"),
    organizationWriteMode: z.enum(["disabled", "legacy-proxy", "dual-write", "identity-native"]).default("disabled"),
    pluginUserWriteMode: z.enum(["disabled", "legacy-proxy", "dual-write", "identity-native"]).default("disabled")
  }),
  legacySessionRevoke: z.object({
    enabled: boolFromEnv.default(false),
    url: optionalStringFromEnv,
    token: optionalStringFromEnv,
    timeoutMs: numberFromEnv.default(800)
  }),
  tokenIssuance: z.object({
    enabled: boolFromEnv.default(false),
    accessTokenTtlSeconds: numberFromEnv.default(10800),
    refreshTokenTtlSeconds: numberFromEnv.default(604800)
  }),
  oidc: z.object({
    enabled: boolFromEnv.default(false),
    issuer: optionalStringFromEnv,
    authorizationEndpointEnabled: boolFromEnv.default(false),
    tokenEndpointEnabled: boolFromEnv.default(false),
    logoutEndpointEnabled: boolFromEnv.default(false),
    requirePkce: boolFromEnv.default(true),
    authorizationCodeTtlSeconds: numberFromEnv.default(300),
    clientsJson: z.string().default("[]"),
    adminMfaRequired: boolFromEnv.default(false)
  }),
  accountLifecycle: z.object({
    enabled: boolFromEnv.default(false),
    mode: z.enum(["disabled", "legacy-proxy", "native"]).default("disabled"),
    legacyApiBaseUrl: optionalStringFromEnv,
    timeoutMs: numberFromEnv.default(1500),
    registerEnabled: boolFromEnv.default(false),
    passwordEnabled: boolFromEnv.default(false),
    passwordChangeNativeEnabled: boolFromEnv.default(false),
    passwordResetNativeEnabled: boolFromEnv.default(false),
    emailVerifyNativeEnabled: boolFromEnv.default(false),
    emailChangeNativeEnabled: boolFromEnv.default(false),
    emailEnabled: boolFromEnv.default(false),
    invitationEnabled: boolFromEnv.default(false),
    invitationManagementNativeEnabled: boolFromEnv.default(false),
    invitationCheckNativeEnabled: boolFromEnv.default(false),
    invitationRecordsNativeEnabled: boolFromEnv.default(false),
    invitationDiagnosticsEnabled: boolFromEnv.default(false)
  }),
  invitationDiagnostics: z.object({
    redisUrl: optionalStringFromEnv,
    scanCount: numberFromEnv.default(100),
    maxKeys: numberFromEnv.default(5000)
  }),
  emailDelivery: z.object({
    webhookUrl: optionalStringFromEnv,
    webhookToken: optionalStringFromEnv
  }),
  emailVerification: z.object({
    codeHashSalt: z.string().default("xrugc-email-verify-v1"),
    codeTtlSeconds: numberFromEnv.default(900),
    rateLimitSeconds: numberFromEnv.default(60),
    maxAttempts: numberFromEnv.default(5),
    lockSeconds: numberFromEnv.default(900)
  }),
  emailChange: z.object({
    tokenTtlSeconds: numberFromEnv.default(600)
  }),
  passwordReset: z.object({
    codeHashSalt: z.string().default("xrugc-password-reset-v1"),
    codeTtlSeconds: numberFromEnv.default(900),
    rateLimitSeconds: numberFromEnv.default(60),
    maxAttempts: numberFromEnv.default(5),
    lockSeconds: numberFromEnv.default(900)
  }),
  jwt: z.object({
    privateKeyPem: optionalStringFromEnv,
    privateKeyFile: optionalStringFromEnv,
    publicKeyPem: optionalStringFromEnv,
    publicKeyFile: optionalStringFromEnv,
    keyId: z.string().default("identity-stage4"),
    issuer: z.string().default("identity-service"),
    audience: optionalStringFromEnv
  }),
  keycloak: z.object({
    baseUrl: z.string().optional()
  }),
  otel: z.object({
    serviceName: z.string().default("identity-adapter"),
    exporterOtlpEndpoint: optionalStringFromEnv,
    exporterOtlpHeaders: optionalStringFromEnv
  })
});

export type IdentityConfig = z.infer<typeof configSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): IdentityConfig {
  return configSchema.parse({
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    readonlyMode: env.IDENTITY_READONLY_MODE,
    jwksPublicKeysJson: env.JWKS_PUBLIC_KEYS_JSON,
    legacyDb: {
      host: env.LEGACY_DB_HOST,
      port: env.LEGACY_DB_PORT,
      name: env.LEGACY_DB_NAME,
      user: env.LEGACY_DB_USER,
      password: env.LEGACY_DB_PASSWORD
    },
    legacyWriteDb: {
      host: env.LEGACY_WRITE_DB_HOST,
      port: env.LEGACY_WRITE_DB_PORT ?? env.LEGACY_DB_PORT,
      name: env.LEGACY_WRITE_DB_NAME ?? env.LEGACY_DB_NAME,
      user: env.LEGACY_WRITE_DB_USER,
      password: env.LEGACY_WRITE_DB_PASSWORD
    },
    identityDb: {
      host: env.IDENTITY_DB_HOST,
      port: env.IDENTITY_DB_PORT,
      name: env.IDENTITY_DB_NAME,
      user: env.IDENTITY_DB_USER,
      password: env.IDENTITY_DB_PASSWORD
    },
    loginAudit: {
      enabled: env.IDENTITY_LOGIN_AUDIT_ENABLED,
      internalToken: env.IDENTITY_INTERNAL_API_TOKEN,
      hashSalt: env.IDENTITY_LOGIN_AUDIT_HASH_SALT
    },
    usageBilling: {
      shadowEnabled: env.IDENTITY_USAGE_BILLING_SHADOW_ENABLED,
      dryRun: env.IDENTITY_USAGE_BILLING_DRY_RUN,
      loginRule: env.IDENTITY_USAGE_BILLING_LOGIN_RULE,
      freeLoginQuota: env.IDENTITY_USAGE_BILLING_FREE_LOGIN_QUOTA,
      subjectStrategy: env.IDENTITY_USAGE_BILLING_SUBJECT_STRATEGY,
      replayBatchSize: env.IDENTITY_USAGE_BILLING_REPLAY_BATCH_SIZE,
      internalToken: env.IDENTITY_USAGE_BILLING_INTERNAL_API_TOKEN ?? env.IDENTITY_INTERNAL_API_TOKEN
    },
    iam: {
      enabled: env.IDENTITY_IAM_ENABLED,
      mode: env.IDENTITY_IAM_MODE,
      fallbackEnabled: env.IDENTITY_IAM_FALLBACK_ENABLED,
      schemaAutoEnsureEnabled: env.IDENTITY_IAM_AUTO_ENSURE_SCHEMA,
      reconciliationEnabled: env.IDENTITY_IAM_RECONCILIATION_ENABLED,
      reconciliationBatchSize: env.IDENTITY_IAM_RECONCILIATION_BATCH_SIZE,
      internalToken: env.IDENTITY_IAM_INTERNAL_API_TOKEN ?? env.IDENTITY_INTERNAL_API_TOKEN,
      userViewEnabled: env.IDENTITY_IAM_USER_VIEW_ENABLED,
      roleViewEnabled: env.IDENTITY_IAM_ROLE_VIEW_ENABLED,
      permissionViewEnabled: env.IDENTITY_IAM_PERMISSION_VIEW_ENABLED,
      organizationViewEnabled: env.IDENTITY_IAM_ORGANIZATION_VIEW_ENABLED,
      pluginViewEnabled: env.IDENTITY_IAM_PLUGIN_VIEW_ENABLED,
      profileWriteMode: env.IDENTITY_IAM_PROFILE_WRITE_MODE,
      roleWriteMode: env.IDENTITY_IAM_ROLE_WRITE_MODE,
      organizationWriteMode: env.IDENTITY_IAM_ORG_WRITE_MODE,
      pluginUserWriteMode: env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE
    },
    legacySessionRevoke: {
      enabled: env.IDENTITY_LEGACY_SESSION_REVOKE_ENABLED,
      url: env.IDENTITY_LEGACY_SESSION_REVOKE_URL,
      token: env.IDENTITY_LEGACY_SESSION_REVOKE_TOKEN ?? env.IDENTITY_INTERNAL_API_TOKEN,
      timeoutMs: env.IDENTITY_LEGACY_SESSION_REVOKE_TIMEOUT_MS
    },
    tokenIssuance: {
      enabled: env.IDENTITY_TOKEN_ISSUANCE_ENABLED,
      accessTokenTtlSeconds: env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTtlSeconds: env.IDENTITY_REFRESH_TOKEN_TTL_SECONDS
    },
    oidc: {
      enabled: env.IDENTITY_OIDC_ENABLED,
      issuer: env.IDENTITY_OIDC_ISSUER,
      authorizationEndpointEnabled: env.IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED,
      tokenEndpointEnabled: env.IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED,
      logoutEndpointEnabled: env.IDENTITY_OIDC_LOGOUT_ENDPOINT_ENABLED,
      requirePkce: env.IDENTITY_OIDC_REQUIRE_PKCE,
      authorizationCodeTtlSeconds: env.IDENTITY_OIDC_AUTHORIZATION_CODE_TTL_SECONDS,
      clientsJson: env.IDENTITY_OIDC_CLIENTS_JSON,
      adminMfaRequired: env.IDENTITY_OIDC_ADMIN_MFA_REQUIRED
    },
    accountLifecycle: {
      enabled: env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED,
      mode: env.IDENTITY_ACCOUNT_LIFECYCLE_MODE,
      legacyApiBaseUrl: env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL,
      timeoutMs: env.IDENTITY_ACCOUNT_LIFECYCLE_TIMEOUT_MS,
      registerEnabled: env.IDENTITY_ACCOUNT_REGISTER_ENABLED,
      passwordEnabled: env.IDENTITY_ACCOUNT_PASSWORD_ENABLED,
      passwordChangeNativeEnabled: env.IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED,
      passwordResetNativeEnabled: env.IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED,
      emailVerifyNativeEnabled: env.IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED,
      emailChangeNativeEnabled: env.IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED,
      emailEnabled: env.IDENTITY_ACCOUNT_EMAIL_ENABLED,
      invitationEnabled: env.IDENTITY_ACCOUNT_INVITATION_ENABLED,
      invitationManagementNativeEnabled: env.IDENTITY_ACCOUNT_INVITATION_MANAGEMENT_NATIVE_ENABLED,
      invitationCheckNativeEnabled: env.IDENTITY_ACCOUNT_INVITATION_CHECK_NATIVE_ENABLED,
      invitationRecordsNativeEnabled: env.IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED,
      invitationDiagnosticsEnabled: env.IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED
    },
    invitationDiagnostics: {
      redisUrl: env.IDENTITY_INVITATION_REDIS_URL,
      scanCount: env.IDENTITY_INVITATION_REDIS_SCAN_COUNT,
      maxKeys: env.IDENTITY_INVITATION_REDIS_MAX_KEYS
    },
    emailDelivery: {
      webhookUrl: env.IDENTITY_EMAIL_WEBHOOK_URL,
      webhookToken: env.IDENTITY_EMAIL_WEBHOOK_TOKEN
    },
    emailVerification: {
      codeHashSalt: env.IDENTITY_EMAIL_CODE_HASH_SALT,
      codeTtlSeconds: env.IDENTITY_EMAIL_CODE_TTL_SECONDS,
      rateLimitSeconds: env.IDENTITY_EMAIL_RATE_LIMIT_SECONDS,
      maxAttempts: env.IDENTITY_EMAIL_MAX_ATTEMPTS,
      lockSeconds: env.IDENTITY_EMAIL_LOCK_SECONDS
    },
    emailChange: {
      tokenTtlSeconds: env.IDENTITY_EMAIL_CHANGE_TOKEN_TTL_SECONDS
    },
    passwordReset: {
      codeHashSalt: env.IDENTITY_PASSWORD_RESET_CODE_HASH_SALT,
      codeTtlSeconds: env.IDENTITY_PASSWORD_RESET_CODE_TTL_SECONDS,
      rateLimitSeconds: env.IDENTITY_PASSWORD_RESET_RATE_LIMIT_SECONDS,
      maxAttempts: env.IDENTITY_PASSWORD_RESET_MAX_ATTEMPTS,
      lockSeconds: env.IDENTITY_PASSWORD_RESET_LOCK_SECONDS
    },
    jwt: {
      privateKeyPem: env.IDENTITY_JWT_PRIVATE_KEY_PEM,
      privateKeyFile: env.IDENTITY_JWT_PRIVATE_KEY_FILE,
      publicKeyPem: env.IDENTITY_JWT_PUBLIC_KEY_PEM,
      publicKeyFile: env.IDENTITY_JWT_PUBLIC_KEY_FILE,
      keyId: env.IDENTITY_JWT_KEY_ID,
      issuer: env.IDENTITY_JWT_ISSUER,
      audience: env.IDENTITY_JWT_AUDIENCE
    },
    keycloak: {
      baseUrl: env.KEYCLOAK_BASE_URL
    },
    otel: {
      serviceName: env.OTEL_SERVICE_NAME,
      exporterOtlpEndpoint: env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT ?? env.OTEL_EXPORTER_OTLP_ENDPOINT,
      exporterOtlpHeaders: env.OTEL_EXPORTER_OTLP_TRACES_HEADERS ?? env.OTEL_EXPORTER_OTLP_HEADERS
    }
  });
}
