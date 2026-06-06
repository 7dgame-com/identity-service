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
  keycloak: z.object({
    baseUrl: z.string().optional()
  }),
  otelServiceName: z.string().default("identity-adapter")
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
    keycloak: {
      baseUrl: env.KEYCLOAK_BASE_URL
    },
    otelServiceName: env.OTEL_SERVICE_NAME
  });
}

