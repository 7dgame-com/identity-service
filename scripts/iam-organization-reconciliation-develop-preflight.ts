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
MySQL snapshots, executes compiled schema/count probes and one-row strict
decoder probes, and prints a sanitized JSON report. It performs no DDL or
write, never enables reconciliation/runtime readiness, and never targets
main, publish, Production, or tmrpp.
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
    validateDevelopDatabaseConfiguration(config, env);
    const report = await runOrganizationReconciliationDevelopSourcePreflight({
      legacyConnectionFactory: connectionFactory(config.legacyDb),
      identityConnectionFactory: connectionFactory(config.identityDb),
      pluginConnectionFactory: connectionFactory({
        ...config.legacyDb,
        name: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
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

function validateDevelopDatabaseConfiguration(config: IdentityConfig, env: NodeJS.ProcessEnv): void {
  if (!config.legacyDb.host || !config.legacyDb.user || !config.legacyDb.password ||
    !config.identityDb.host || !config.identityDb.user || !config.identityDb.password) {
    throw new Error("The Develop database configuration is incomplete.");
  }
  if (config.identityDb.name !== "xrugc_identity_dev") {
    throw new Error("The Identity database is not the compiled xrteeth Develop database.");
  }
  const pluginDatabase = env.PLUGIN_DB_NAME ?? ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE;
  if (pluginDatabase !== ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE) {
    throw new Error("The plugin database is not the compiled Develop source.");
  }
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
