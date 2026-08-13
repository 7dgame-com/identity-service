import mysql from "mysql2/promise";
import { pathToFileURL } from "node:url";
import { loadConfig, type IdentityConfig } from "../apps/identity-adapter/src/config.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-source-catalog.js";
import {
  runOrganizationReconciliationDevelopPhysicalProbe,
  type OrganizationReconciliationDevelopPhysicalProbeDependencies,
  type OrganizationReconciliationDevelopPhysicalProbeReport
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-physical-probe.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "../apps/identity-adapter/src/iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../apps/identity-adapter/src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const DATABASE_QUERY_TIMEOUT_MS = 10_000;

export const organizationReconciliationDevelopPhysicalProbeHelp = `Usage:
  npm --silent run iam:organization-reconciliation:develop-physical-probe -- --environment=xrteeth-develop

Runs two independent, read-only REPEATABLE READ metadata probes against each
of the three dedicated xrteeth Develop source identities. The command checks
the compiled 21-dataset / 19-physical-table closure, exact database and current
user bindings, direct bounded grants, tables, columns, indexes, collations and
the MySQL-vs-Node UTF-8 binary ordering witness. Exact visible full-length
UNIQUE BTREE keys prove deterministic cursor closure; this is not an optimizer
plan or ORDER BY performance claim. A successful exact READ ONLY snapshot start
and the verified REPEATABLE READ session default form the transaction protocol;
the command does not claim unreliable current-transaction variable introspection.
All three read-only users must differ from one another and from the explicitly
supplied Legacy, Identity and plugin service usernames.
It emits one sanitized JSON line only; it never emits
connection values, credentials, grant text, business rows or raw errors, and
never enables any READY or production state.
`;

export const ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_LAUNCH_DIAGNOSTIC_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-physical-probe-launch-diagnostic/v1" as const;

type PhysicalProbeConfigurationFailure =
  | "plugin-service-user-missing"
  | "invalid-physical-probe-configuration";

class PhysicalProbeConfigurationError extends Error {
  constructor(readonly failureId: PhysicalProbeConfigurationFailure) {
    super(failureId);
    this.name = "PhysicalProbeConfigurationError";
  }
}

interface DatabaseConfiguration {
  readonly host: string;
  readonly port: number;
  readonly name: string;
  readonly user: string;
  readonly password: string;
}

export interface OrganizationReconciliationDevelopPhysicalProbeCliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export interface OrganizationReconciliationDevelopPhysicalProbeCliRuntime {
  readonly connectionFactory?: (configuration: DatabaseConfiguration) => MysqlRepeatableReadSnapshotConnectionFactory;
  readonly executeProbe?: (
    dependencies: OrganizationReconciliationDevelopPhysicalProbeDependencies
  ) => Promise<OrganizationReconciliationDevelopPhysicalProbeReport>;
}

export async function runOrganizationReconciliationDevelopPhysicalProbeCli(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OrganizationReconciliationDevelopPhysicalProbeCliIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  },
  runtime: OrganizationReconciliationDevelopPhysicalProbeCliRuntime = {}
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationDevelopPhysicalProbeHelp);
    return 0;
  }
  if (argv.length !== 1 || argv[0] !== "--environment=xrteeth-develop") {
    io.stderr("Invalid arguments. Use --environment=xrteeth-develop.\n");
    return 2;
  }

  try {
    const configurations = resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(
      loadConfig(env),
      env
    );
    const makeFactory = runtime.connectionFactory ?? connectionFactory;
    const executeProbe = runtime.executeProbe ?? runOrganizationReconciliationDevelopPhysicalProbe;
    const report = await executeProbe({
      legacyConnectionFactory: makeFactory(configurations["legacy-main"]),
      identityConnectionFactory: makeFactory(configurations.identity),
      pluginConnectionFactory: makeFactory(configurations.plugin),
      expectedDatabaseUsers: Object.freeze({
        "legacy-main": configurations["legacy-main"].user,
        identity: configurations.identity.user,
        plugin: configurations.plugin.user
      }),
      buildRevision: env.IDENTITY_BUILD_REVISION ?? "unknown"
    });
    io.stdout(`${JSON.stringify(report)}\n`);
    return report.passed ? 0 : 1;
  } catch (error) {
    if (error instanceof PhysicalProbeConfigurationError) {
      io.stderr(`${JSON.stringify({
        contract: ORGANIZATION_RECONCILIATION_DEVELOP_PHYSICAL_PROBE_LAUNCH_DIAGNOSTIC_CONTRACT,
        environment: "xrteeth-develop",
        mode: "read-only",
        passed: false,
        failure: error.failureId
      })}\n`);
    } else {
      io.stderr("The xrteeth Develop physical probe could not run.\n");
    }
    return 2;
  }
}

export function resolveOrganizationReconciliationDevelopPhysicalProbeConfiguration(
  config: IdentityConfig,
  env: NodeJS.ProcessEnv
): Readonly<Record<OrganizationReconciliationMysqlRawComponentId, DatabaseConfiguration>> {
  const pluginPort = Number(env.PLUGIN_DB_PORT ?? "3306");
  const candidates = {
    "legacy-main": {
      host: config.legacyDb.host,
      port: config.legacyDb.port,
      name: config.legacyDb.name,
      user: env.IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_USER,
      password: env.IDENTITY_IAM_ORG_RECONCILIATION_LEGACY_DB_PASSWORD
    },
    identity: {
      host: config.identityDb.host,
      port: config.identityDb.port,
      name: config.identityDb.name,
      user: env.IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_USER,
      password: env.IDENTITY_IAM_ORG_RECONCILIATION_IDENTITY_DB_PASSWORD
    },
    plugin: {
      host: env.PLUGIN_DB_HOST,
      port: pluginPort,
      name: env.PLUGIN_DB_NAME,
      user: env.PLUGIN_DB_USER,
      password: env.PLUGIN_DB_PASSWORD
    }
  } as const;
  const pluginServiceUser = env.IDENTITY_IAM_ORG_RECONCILIATION_PLUGIN_SERVICE_DB_USER;
  if (pluginServiceUser === undefined || pluginServiceUser.length === 0) {
    throw new PhysicalProbeConfigurationError("plugin-service-user-missing");
  }
  const serviceUsers = [config.legacyDb.user, config.identityDb.user, pluginServiceUser];
  if (!serviceUsers.every((user) => typeof user === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(user)) ||
    new Set(serviceUsers).size !== 3) {
    throw new PhysicalProbeConfigurationError("invalid-physical-probe-configuration");
  }
  const expectedNames = {
    "legacy-main": ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
    identity: ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
    plugin: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
  } as const;
  const users = Object.values(candidates).map((candidate) => candidate.user);
  if (new Set(users).size !== 3 || users.some((user) => serviceUsers.includes(user as string))) {
    throw new PhysicalProbeConfigurationError("invalid-physical-probe-configuration");
  }

  const output = {} as Record<OrganizationReconciliationMysqlRawComponentId, DatabaseConfiguration>;
  for (const componentId of ["legacy-main", "identity", "plugin"] as const) {
    const candidate = candidates[componentId];
    if (candidate.name !== expectedNames[componentId] ||
      typeof candidate.host !== "string" || candidate.host.length < 1 || candidate.host.length > 255 ||
      !Number.isInteger(candidate.port) || candidate.port < 1 || candidate.port > 65_535 ||
      typeof candidate.user !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(candidate.user) ||
      typeof candidate.password !== "string" || candidate.password.length < 1 || candidate.password.length > 4_096) {
      throw new PhysicalProbeConfigurationError("invalid-physical-probe-configuration");
    }
    output[componentId] = Object.freeze({
      host: candidate.host,
      port: candidate.port,
      name: candidate.name,
      user: candidate.user,
      password: candidate.password
    });
  }
  return Object.freeze(output);
}

function connectionFactory(configuration: DatabaseConfiguration): MysqlRepeatableReadSnapshotConnectionFactory {
  const captured = Object.freeze({
    host: configuration.host,
    port: configuration.port,
    database: configuration.name,
    user: configuration.user,
    password: configuration.password
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
        connection.query({ sql, timeout: DATABASE_QUERY_TIMEOUT_MS }, [...parameters]),
      release: async () => connection.end()
    });
  };
}

async function main(): Promise<void> {
  process.exitCode = await runOrganizationReconciliationDevelopPhysicalProbeCli(
    process.argv.slice(2),
    process.env
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
