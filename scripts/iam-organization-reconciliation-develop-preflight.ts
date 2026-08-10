import mysql from "mysql2/promise";
import { pathToFileURL } from "node:url";
import { loadConfig, type IdentityConfig } from "../apps/identity-adapter/src/config.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  runOrganizationReconciliationDevelopSourcePreflight
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-source-preflight.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../apps/identity-adapter/src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

export const organizationReconciliationDevelopPreflightHelp = `Usage:
  npm run iam:organization-reconciliation:develop-preflight -- --environment=xrteeth-develop

This command is restricted to xrteeth Develop. It opens only fixed read-only
MySQL snapshots, verifies exact database bindings and current-user read-only
grants, executes compiled schema/count probes and one-row strict decoder
probes, and prints a sanitized JSON report. It performs no DDL or
write, never enables reconciliation/runtime readiness, and never targets
main, publish, Production, or tmrpp. Legacy, Identity, and plugin sources each
require a distinct dedicated read-only credential; service credentials are
never reused.
`;

export interface OrganizationReconciliationDevelopPreflightCliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export async function runOrganizationReconciliationDevelopPreflightCli(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OrganizationReconciliationDevelopPreflightCliIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  }
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationDevelopPreflightHelp);
    return 0;
  }
  if (argv.length !== 1 || argv[0] !== "--environment=xrteeth-develop") {
    io.stderr("Invalid arguments. Use --environment=xrteeth-develop.\n");
    return 2;
  }

  try {
    const config = loadConfig(env);
    const databases = validateDevelopDatabaseConfiguration(config, env);
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: connectionFactory(databases.legacy),
      identityConnectionFactory: connectionFactory(databases.identity),
      pluginConnectionFactory: connectionFactory(databases.plugin),
      expectedDatabaseUsers: Object.freeze({
        "legacy-main": databases.legacy.user,
        identity: databases.identity.user,
        plugin: databases.plugin.user
      }),
      buildRevision: env.IDENTITY_BUILD_REVISION ?? "unknown",
      now: () => new Date()
    });
    io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return report.passed ? 0 : 1;
  } catch {
    io.stderr("The xrteeth Develop read-only source preflight could not run.\n");
    return 2;
  }
}

export function validateDevelopDatabaseConfiguration(config: IdentityConfig, env: NodeJS.ProcessEnv): {
  readonly legacy: { readonly host: string; readonly port: number; readonly name: string; readonly user: string; readonly password: string };
  readonly identity: { readonly host: string; readonly port: number; readonly name: string; readonly user: string; readonly password: string };
  readonly plugin: { readonly host: string; readonly port: number; readonly name: string; readonly user: string; readonly password: string };
} {
  if (!config.legacyDb.host || !config.identityDb.host) {
    throw new Error("The Develop database configuration is incomplete.");
  }
  if (config.legacyDb.name !== "bujiaban" || config.identityDb.name !== "xrugc_identity_dev") {
    throw new Error("The service databases are not the compiled xrteeth Develop sources.");
  }
  const pluginDatabase = env.PLUGIN_DB_NAME;
  if (pluginDatabase !== ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE) {
    throw new Error("The plugin database is not the compiled Develop source.");
  }
  const pluginPort = Number(env.PLUGIN_DB_PORT ?? "3306");
  const legacyUser = env.IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER;
  const legacyPassword = env.IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD;
  const identityUser = env.IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER;
  const identityPassword = env.IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD;
  if (!env.PLUGIN_DB_HOST || !env.PLUGIN_DB_USER || !env.PLUGIN_DB_PASSWORD ||
    !legacyUser || !legacyPassword || !identityUser || !identityPassword ||
    ![legacyUser, identityUser, env.PLUGIN_DB_USER].every((user) => /^[A-Za-z0-9_.-]{1,64}$/.test(user)) ||
    !Number.isInteger(pluginPort) || pluginPort < 1 || pluginPort > 65_535 ||
    new Set([legacyUser, identityUser, env.PLUGIN_DB_USER]).size !== 3 ||
    [legacyUser, identityUser, env.PLUGIN_DB_USER].some((user) =>
      user === config.legacyDb.user || user === config.identityDb.user)) {
    throw new Error("The dedicated Develop reconciliation read-only database configuration is incomplete.");
  }
  return Object.freeze({
    legacy: Object.freeze({
      host: config.legacyDb.host,
      port: config.legacyDb.port,
      name: config.legacyDb.name,
      user: legacyUser,
      password: legacyPassword
    }),
    identity: Object.freeze({
      host: config.identityDb.host,
      port: config.identityDb.port,
      name: config.identityDb.name,
      user: identityUser,
      password: identityPassword
    }),
    plugin: Object.freeze({
      host: env.PLUGIN_DB_HOST,
      port: pluginPort,
      name: pluginDatabase,
      user: env.PLUGIN_DB_USER,
      password: env.PLUGIN_DB_PASSWORD
    })
  });
}

function connectionFactory(config: {
  readonly host?: string;
  readonly port: number;
  readonly name: string;
  readonly user?: string;
  readonly password?: string;
}): MysqlRepeatableReadSnapshotConnectionFactory {
  const captured = Object.freeze({
    host: config.host as string,
    port: config.port,
    database: config.name,
    user: config.user as string,
    password: config.password as string
  });
  return async () => {
    const connection = await mysql.createConnection({
      ...captured,
      charset: "utf8mb4",
      connectTimeout: 5_000,
      multipleStatements: false,
      supportBigNumbers: true,
      bigNumberStrings: true
    });
    return Object.freeze({
      query: async (sql: string, parameters: readonly unknown[] = []) =>
        connection.query(sql, [...parameters]),
      release: async () => connection.end()
    });
  };
}

async function main(): Promise<void> {
  process.exitCode = await runOrganizationReconciliationDevelopPreflightCli(
    process.argv.slice(2),
    process.env
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
