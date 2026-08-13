import mysql from "mysql2/promise";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadConfig, type IdentityConfig } from
  "../apps/identity-adapter/src/config.js";
import {
  OrganizationReconciliationDevelopFullRangeError,
  assertOrganizationReconciliationDevelopFullRangeCompiledRevision,
  assertOrganizationReconciliationDevelopFullRangeTrustProfileProvisioned,
  runOrganizationReconciliationDevelopFullRange,
  type OrganizationReconciliationDevelopFullRangeDependencies,
  type OrganizationReconciliationDevelopFullRangeExternalSigner,
  type OrganizationReconciliationDevelopFullRangeResult
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-full-range.js";
import {
  OrganizationReconciliationDevelopHashSignerTransportConfigError,
  assertOrganizationReconciliationDevelopHashSignerTransportConfigPath,
  loadOrganizationReconciliationDevelopHashSignerTransportConfig
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-hash-signer-transport-config.js";
import {
  createOrganizationReconciliationDevelopDeploymentEvidenceSha256,
  parseOrganizationReconciliationDevelopDeploymentEvidence,
  type OrganizationReconciliationDevelopDeploymentEvidence
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-deployment-evidence.js";
import {
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustPolicy
} from "../apps/identity-adapter/src/iam-organization-reconciliation-provenance.js";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
  ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-source-catalog.js";
import type {
  OrganizationReconciliationMysqlRawComponentId
} from "../apps/identity-adapter/src/iam-organization-reconciliation/mysql-source-adapters/raw-source-snapshots.js";
import type {
  MysqlRepeatableReadSnapshotConnectionFactory
} from "../apps/identity-adapter/src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const DATABASE_QUERY_TIMEOUT_MS = 10_000;
const MAX_OUTPUT_BYTES = 512 * 1024 * 1024;

export const organizationReconciliationDevelopFullRangeHelp = `Usage:
  npm --silent run iam:organization-reconciliation:develop-full-range -- \\
    --environment=xrteeth-develop \\
    --build-revision=<expected-full-40-character-lowercase-git-sha> \\
    --deployment-evidence=<absolute-0600-json-path-inside-this-repository> \\
    --trust-policy=<absolute-0600-json-path-inside-this-repository> \\
    --signer-transport=<absolute-owner-0600-json-path> \\
    --output=<absolute-json-path-inside-this-repository>

Runs the fixed Develop-only, read-only 21-dataset / eight-surface full-range
pipeline. It fails before RNG, clock, output or database I/O while either owner
context execution state is not explicitly reviewed and authorized. The raw
canonical artifact is created once with O_EXCL and mode 0600; stdout contains
only the completion status and exact file SHA-256. It never writes a database,
enables READY, or targets Production/tmrpp.

The trust-policy JSON contains public collector metadata/public keys only. The
deployment-evidence JSON is parsed and domain-hashed before database, RNG,
signer fetch, or output writes; it must bind the compiled revision, one release
image digest, and one signer observation matching policy. Task 7.2 does not
claim physical independence and never permits Production promotion.
The signer-transport JSON selects exactly one compiled-profile key ID, HTTPS
endpoint, absolute owner-0600 bearer-token file, and explicit owner-0600
private-CA certificate file. The client verifies both the private CA chain and
the deployment-evidence leaf DER SHA-256, without system/global CA state. It cannot supply or
override collector/node/key fingerprints, build revision, or private keys, and
is fully validated before DB, network, or output writes. Its exact top-level
fields are contract, environment, profileId, and signers; each signer contains
only keyId, endpoint, bearerTokenFile, and certificateAuthorityFile. Tokens
remain in their local files.
The build-revision argument is only an equality assertion against the immutable
revision compiled before tsc; it never supplies or overrides evidence metadata.
`;

export const ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_LAUNCH_DIAGNOSTIC_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-full-range-launch-diagnostic/v1" as const;

interface DatabaseConfiguration {
  readonly host: string;
  readonly port: number;
  readonly name: string;
  readonly user: string;
  readonly password: string;
}

export interface OrganizationReconciliationDevelopFullRangeCliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export interface OrganizationReconciliationDevelopFullRangeCliRuntime {
  readonly repositoryRoot?: string;
  readonly connectionFactory?: (
    configuration: DatabaseConfiguration
  ) => MysqlRepeatableReadSnapshotConnectionFactory;
  readonly executeFullRange?: (
    dependencies: OrganizationReconciliationDevelopFullRangeDependencies
  ) => Promise<OrganizationReconciliationDevelopFullRangeResult>;
  readonly assertTrustProfileProvisioned?: () => void;
  readonly loadTrustPolicy?: (path: string, repositoryRoot: string) =>
    Promise<OrganizationReconciliationTrustPolicy> | OrganizationReconciliationTrustPolicy;
  readonly loadDeploymentEvidence?: (path: string, repositoryRoot: string) =>
    Promise<OrganizationReconciliationDevelopDeploymentEvidence> |
    OrganizationReconciliationDevelopDeploymentEvidence;
  readonly externalSigners?: readonly OrganizationReconciliationDevelopFullRangeExternalSigner[];
  readonly attestationTtlSeconds?: number;
}

interface ParsedArguments {
  readonly expectedBuildRevision: string;
  readonly deploymentEvidencePath: string;
  readonly trustPolicyPath: string;
  readonly signerTransportPath: string;
  readonly outputPath: string;
}

class FullRangeCliError extends Error {
  constructor(readonly failureId:
    | "invalid-arguments"
    | "invalid-configuration"
    | "invalid-deployment-evidence"
    | "invalid-signer-transport"
    | "invalid-output-path"
    | "execution-not-authorized"
    | "run-failed") {
    super(failureId);
    this.name = "FullRangeCliError";
  }
}

export async function runOrganizationReconciliationDevelopFullRangeCli(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  io: OrganizationReconciliationDevelopFullRangeCliIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  },
  runtime: OrganizationReconciliationDevelopFullRangeCliRuntime = {}
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationDevelopFullRangeHelp);
    return 0;
  }

  let parsed: ParsedArguments;
  let repositoryRoot: string;
  try {
    parsed = parseArguments(argv);
    repositoryRoot = validateLexicalOutputPath(
      parsed.outputPath,
      runtime.repositoryRoot ?? process.cwd()
    );
    validateLexicalOutputPath(parsed.trustPolicyPath, repositoryRoot);
    validateLexicalOutputPath(parsed.deploymentEvidencePath, repositoryRoot);
    assertOrganizationReconciliationDevelopHashSignerTransportConfigPath(
      parsed.signerTransportPath
    );
  } catch {
    io.stderr("Invalid arguments or output path. Use --help.\n");
    return 2;
  }

  try {
    const compiledBuildRevision =
      assertOrganizationReconciliationDevelopFullRangeCompiledRevision(
        parsed.expectedBuildRevision
      );
    (runtime.assertTrustProfileProvisioned ??
      assertOrganizationReconciliationDevelopFullRangeTrustProfileProvisioned)();
    await assertOrdinaryMissingOutputPath(parsed.outputPath, repositoryRoot);
    const trustPolicy = await (runtime.loadTrustPolicy ?? readOrdinary0600TrustPolicy)(
      parsed.trustPolicyPath,
      repositoryRoot
    );
    const deploymentEvidence = await (
      runtime.loadDeploymentEvidence ?? readOrdinary0600DeploymentEvidence
    )(parsed.deploymentEvidencePath, repositoryRoot);
    const externalSigners = runtime.externalSigners ??
      await loadOrganizationReconciliationDevelopHashSignerTransportConfig(
        parsed.signerTransportPath,
        trustPolicy,
        deploymentEvidence
      );
    const configurations = resolveOrganizationReconciliationDevelopFullRangeConfiguration(
      loadConfig(env),
      env
    );
    const makeFactory = runtime.connectionFactory ?? connectionFactory;
    const execute = runtime.executeFullRange ?? runOrganizationReconciliationDevelopFullRange;
    const result = await execute({
      environment: "xrteeth-develop",
      deploymentEvidence,
      legacyConnectionFactory: makeFactory(configurations["legacy-main"]),
      identityConnectionFactory: makeFactory(configurations.identity),
      pluginConnectionFactory: makeFactory(configurations.plugin),
      expectedDatabaseUsers: Object.freeze({
        "legacy-main": configurations["legacy-main"].user,
        identity: configurations.identity.user,
        plugin: configurations.plugin.user
      }),
      trustPolicy,
      externalSigners,
      attestationTtlSeconds: runtime.attestationTtlSeconds ?? 300,
      clock: Object.freeze({ now: () => new Date() }),
      output: createExclusive0600Output(parsed.outputPath, repositoryRoot)
    });
    const deploymentEvidenceSha256 =
      createOrganizationReconciliationDevelopDeploymentEvidenceSha256(deploymentEvidence);
    if (
      result.buildRevision !== compiledBuildRevision ||
      result.deploymentEvidenceSha256 !== deploymentEvidenceSha256 ||
      result.releaseImageDigest !== deploymentEvidence.releaseImageDigest
    ) {
      throw new FullRangeCliError("run-failed");
    }
    io.stdout(`${JSON.stringify({ status: result.outcome, sha256: result.outputSha256 })}\n`);
    return 0;
  } catch (error) {
    const failure = error instanceof OrganizationReconciliationDevelopFullRangeError
      ? error.failureId
      : error instanceof OrganizationReconciliationDevelopHashSignerTransportConfigError
        ? "invalid-signer-transport"
        : error instanceof FullRangeCliError
          ? error.failureId
          : "run-failed";
    io.stderr(`${JSON.stringify({
      contract: ORGANIZATION_RECONCILIATION_DEVELOP_FULL_RANGE_LAUNCH_DIAGNOSTIC_CONTRACT,
      environment: "xrteeth-develop",
      mode: "read-only",
      status: "failed",
      failure
    })}\n`);
    return [
      "compiled-revision-unavailable",
      "deployment-evidence-invalid",
      "trust-profile-not-provisioned",
      "trust-profile-mismatch",
      "signer-not-provisioned",
      "signer-failed",
      "attestation-verification-failed",
      "execution-not-authorized"
    ].includes(failure) ? 1 : 2;
  }
}

export function resolveOrganizationReconciliationDevelopFullRangeConfiguration(
  config: IdentityConfig,
  env: NodeJS.ProcessEnv
): Readonly<Record<OrganizationReconciliationMysqlRawComponentId, DatabaseConfiguration>> {
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
      port: Number(env.PLUGIN_DB_PORT ?? "3306"),
      name: env.PLUGIN_DB_NAME,
      user: env.PLUGIN_DB_USER,
      password: env.PLUGIN_DB_PASSWORD
    }
  } as const;
  const expectedNames = {
    "legacy-main": ORGANIZATION_RECONCILIATION_DEVELOP_LEGACY_DATABASE,
    identity: ORGANIZATION_RECONCILIATION_DEVELOP_IDENTITY_DATABASE,
    plugin: ORGANIZATION_RECONCILIATION_DEVELOP_PLUGIN_DATABASE
  } as const;
  const output = {} as Record<OrganizationReconciliationMysqlRawComponentId, DatabaseConfiguration>;
  for (const componentId of ["legacy-main", "identity", "plugin"] as const) {
    const candidate = candidates[componentId];
    if (
      candidate.name !== expectedNames[componentId] ||
      typeof candidate.host !== "string" || candidate.host.length < 1 || candidate.host.length > 255 ||
      !Number.isInteger(candidate.port) || candidate.port < 1 || candidate.port > 65_535 ||
      typeof candidate.user !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(candidate.user) ||
      typeof candidate.password !== "string" || candidate.password.length < 1 ||
      candidate.password.length > 4_096
    ) {
      throw new FullRangeCliError("invalid-configuration");
    }
    output[componentId] = Object.freeze({
      host: candidate.host,
      port: candidate.port,
      name: candidate.name,
      user: candidate.user,
      password: candidate.password
    });
  }
  const users = Object.values(output).map((candidate) => candidate.user);
  if (new Set(users).size !== 3) throw new FullRangeCliError("invalid-configuration");
  return Object.freeze(output);
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  if (!Array.isArray(argv) || argv.length !== 6) {
    throw new FullRangeCliError("invalid-arguments");
  }
  const values = new Map<string, string>();
  for (const argument of argv) {
    if (typeof argument !== "string") throw new FullRangeCliError("invalid-arguments");
    const separator = argument.indexOf("=");
    if (separator < 3) throw new FullRangeCliError("invalid-arguments");
    const key = argument.slice(0, separator);
    const value = argument.slice(separator + 1);
    if (values.has(key)) throw new FullRangeCliError("invalid-arguments");
    values.set(key, value);
  }
  if (
    values.size !== 6 ||
    values.get("--environment") !== "xrteeth-develop" ||
    !/^[a-f0-9]{40}$/.test(values.get("--build-revision") ?? "") ||
    !values.has("--deployment-evidence") ||
    !values.has("--trust-policy") ||
    !values.has("--signer-transport") ||
    !values.has("--output")
  ) {
    throw new FullRangeCliError("invalid-arguments");
  }
  return Object.freeze({
    expectedBuildRevision: values.get("--build-revision")!,
    deploymentEvidencePath: values.get("--deployment-evidence")!,
    trustPolicyPath: values.get("--trust-policy")!,
    signerTransportPath: values.get("--signer-transport")!,
    outputPath: values.get("--output")!
  });
}

function validateLexicalOutputPath(outputPath: string, candidateRepositoryRoot: string): string {
  if (
    typeof outputPath !== "string" || typeof candidateRepositoryRoot !== "string" ||
    outputPath.length < 2 || outputPath.length > 4_096 || outputPath.includes("\0") ||
    candidateRepositoryRoot.length < 1 || candidateRepositoryRoot.length > 4_096 ||
    !isAbsolute(outputPath) || !isAbsolute(candidateRepositoryRoot) ||
    resolve(outputPath) !== outputPath || resolve(candidateRepositoryRoot) !== candidateRepositoryRoot ||
    extname(outputPath) !== ".json" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$/.test(basename(outputPath))
  ) {
    throw new FullRangeCliError("invalid-output-path");
  }
  const scoped = relative(candidateRepositoryRoot, outputPath);
  if (scoped.length < 1 || scoped === ".." || scoped.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(scoped)) {
    throw new FullRangeCliError("invalid-output-path");
  }
  return candidateRepositoryRoot;
}

async function readOrdinary0600TrustPolicy(
  policyPath: string,
  repositoryRoot: string
): Promise<OrganizationReconciliationTrustPolicy> {
  return parseOrganizationReconciliationTrustPolicy(
    await readOrdinary0600Json(policyPath, repositoryRoot)
  );
}

async function readOrdinary0600DeploymentEvidence(
  evidencePath: string,
  repositoryRoot: string
): Promise<OrganizationReconciliationDevelopDeploymentEvidence> {
  try {
    return parseOrganizationReconciliationDevelopDeploymentEvidence(
      await readOrdinary0600Json(evidencePath, repositoryRoot)
    );
  } catch {
    throw new FullRangeCliError("invalid-deployment-evidence");
  }
}

async function readOrdinary0600Json(
  policyPath: string,
  repositoryRoot: string
): Promise<unknown> {
  validateLexicalOutputPath(policyPath, repositoryRoot);
  if (typeof fsConstants.O_NOFOLLOW !== "number" || typeof fsConstants.O_NONBLOCK !== "number") {
    throw new FullRangeCliError("invalid-configuration");
  }
  const flags = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  let bytes: Buffer | null = null;
  try {
    const parentPath = dirname(policyPath);
    const [rootStat, parentStat, policyStat] = await Promise.all([
      lstat(repositoryRoot),
      lstat(parentPath),
      lstat(policyPath)
    ]);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() ||
      !parentStat.isDirectory() || parentStat.isSymbolicLink() ||
      !policyStat.isFile() || policyStat.isSymbolicLink() || policyStat.nlink !== 1 ||
      (policyStat.mode & 0o777) !== 0o600 || policyStat.size < 2 || policyStat.size > 1024 * 1024 ||
      (typeof process.getuid === "function" && policyStat.uid !== process.getuid())) {
      throw new FullRangeCliError("invalid-configuration");
    }
    const [rootReal, parentReal, policyReal] = await Promise.all([
      realpath(repositoryRoot), realpath(parentPath), realpath(policyPath)
    ]);
    if (
      parentReal !== parentPath || policyReal !== policyPath ||
      policyReal !== resolve(rootReal, relative(repositoryRoot, policyPath))
    ) {
      throw new FullRangeCliError("invalid-configuration");
    }
    handle = await open(policyPath, flags);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o777) !== 0o600 ||
      opened.dev !== policyStat.dev || opened.ino !== policyStat.ino || opened.size !== policyStat.size ||
      opened.mtimeMs !== policyStat.mtimeMs || opened.ctimeMs !== policyStat.ctimeMs ||
      (typeof process.getuid === "function" && opened.uid !== process.getuid())) {
      throw new FullRangeCliError("invalid-configuration");
    }
    bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
      if (bytesRead < 1) throw new FullRangeCliError("invalid-configuration");
      offset += bytesRead;
    }
    const overflow = Buffer.alloc(1);
    try {
      if ((await handle.read(overflow, 0, 1, bytes.byteLength)).bytesRead !== 0) {
        throw new FullRangeCliError("invalid-configuration");
      }
    } finally {
      overflow.fill(0);
    }
    const after = await handle.stat();
    if (
      after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || after.nlink !== 1 ||
      (after.mode & 0o777) !== 0o600
    ) throw new FullRangeCliError("invalid-configuration");
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof FullRangeCliError) throw error;
    throw new FullRangeCliError("invalid-configuration");
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

function createExclusive0600Output(
  outputPath: string,
  repositoryRoot: string
): OrganizationReconciliationDevelopFullRangeDependencies["output"] {
  return Object.freeze({
    write: async (payload: string) => {
      if (
        typeof payload !== "string" || !payload.endsWith("\n") ||
        payload.length < 3 || Buffer.byteLength(payload, "utf8") > MAX_OUTPUT_BYTES
      ) {
        throw new FullRangeCliError("run-failed");
      }
      await assertOrdinaryMissingOutputPath(outputPath, repositoryRoot);

      const flags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY |
        (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0);
      let handle: Awaited<ReturnType<typeof open>> | null = null;
      let created: Awaited<ReturnType<Awaited<ReturnType<typeof open>>["stat"]>> | null = null;
      let failure: FullRangeCliError | null = null;
      try {
        handle = await open(outputPath, flags, 0o600);
        await handle.chmod(0o600);
        created = await handle.stat();
        if (!created.isFile() || created.nlink !== 1 || (created.mode & 0o777) !== 0o600) {
          throw new FullRangeCliError("invalid-output-path");
        }
        await handle.writeFile(payload, { encoding: "utf8" });
        await handle.sync();
        const completed = await handle.stat();
        if (
          completed.dev !== created.dev || completed.ino !== created.ino ||
          !completed.isFile() || completed.nlink !== 1 || (completed.mode & 0o777) !== 0o600 ||
          completed.size !== Buffer.byteLength(payload, "utf8")
        ) throw new FullRangeCliError("run-failed");
      } catch (error) {
        failure = error instanceof FullRangeCliError
          ? error
          : new FullRangeCliError("run-failed");
      } finally {
        await handle?.close().catch(() => undefined);
      }
      if (failure !== null) {
        if (created !== null) {
          try {
            const current = await lstat(outputPath);
            if (current.isFile() && current.dev === created.dev && current.ino === created.ino) {
              await unlink(outputPath);
            }
          } catch {
            // Best-effort cleanup is limited to the exact inode created here.
          }
        }
        throw failure;
      }
    }
  });
}

async function assertOrdinaryMissingOutputPath(
  outputPath: string,
  repositoryRoot: string
): Promise<void> {
  const parent = dirname(outputPath);
  let rootReal: string;
  let parentReal: string;
  try {
    const [rootStat, parentStat] = await Promise.all([lstat(repositoryRoot), lstat(parent)]);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink() ||
      !parentStat.isDirectory() || parentStat.isSymbolicLink()) {
      throw new FullRangeCliError("invalid-output-path");
    }
    [rootReal, parentReal] = await Promise.all([realpath(repositoryRoot), realpath(parent)]);
  } catch (error) {
    if (error instanceof FullRangeCliError) throw error;
    throw new FullRangeCliError("invalid-output-path");
  }
  const expectedParentReal = resolve(rootReal, relative(repositoryRoot, parent));
  const parentScope = relative(rootReal, parentReal);
  if (
    parentReal !== expectedParentReal || parentScope === ".." ||
    parentScope.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(parentScope)
  ) {
    throw new FullRangeCliError("invalid-output-path");
  }
  try {
    await lstat(outputPath);
    throw new FullRangeCliError("invalid-output-path");
  } catch (error) {
    if (error instanceof FullRangeCliError) throw error;
    if (!isMissingPathError(error)) throw new FullRangeCliError("invalid-output-path");
  }
}

function isMissingPathError(error: unknown): boolean {
  return error !== null && typeof error === "object" &&
    "code" in error && (error as { readonly code?: unknown }).code === "ENOENT";
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
  process.exitCode = await runOrganizationReconciliationDevelopFullRangeCli(
    process.argv.slice(2),
    process.env
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
