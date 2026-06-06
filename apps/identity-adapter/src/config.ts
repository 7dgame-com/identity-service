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
