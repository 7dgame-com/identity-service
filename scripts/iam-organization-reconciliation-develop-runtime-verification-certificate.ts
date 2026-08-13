import { constants as fsConstants, type BigIntStats } from "node:fs";
import { lstat, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  createOrganizationReconciliationDevelopRuntimeCertificate,
  OrganizationReconciliationDevelopRuntimeCertificateError,
  serializeOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCloseout,
  verifyOrganizationReconciliationDevelopRuntimeCertificate,
  type CreateOrganizationReconciliationDevelopRuntimeCertificateInput,
  type OrganizationReconciliationDevelopRuntimeCertificateArtifacts,
  type VerifyOrganizationReconciliationDevelopRuntimeCertificateInput
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedProfile
} from "../apps/identity-adapter/src/iam-organization-reconciliation-provenance.js";
import {
  resolveCompiledOrganizationReconciliationTrustProfile
} from "../apps/identity-adapter/src/iam-organization-reconciliation-trust-profiles.js";

const MAX_RAW_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_PUBLIC_ARTIFACT_BYTES = 4 * 1024 * 1024;

export const organizationReconciliationDevelopRuntimeCertificateHelp = `Usage:
  npm --silent run iam:organization-reconciliation:develop-runtime-certificate -- \\
    --create --environment=xrteeth-develop \\
    --raw=<absolute-owner-0600-json-path-inside-this-repository> \\
    --deployment-evidence=<absolute-owner-0600-json-path-inside-this-repository> \\
    --physical-probe=<absolute-owner-0600-json-path-inside-this-repository> \\
    --trust-policy=<absolute-owner-0600-json-path-inside-this-repository> \\
    --certificate=<absolute-new-json-path-inside-this-repository> \\
    --closeout=<absolute-new-json-path-inside-this-repository>

  npm --silent run iam:organization-reconciliation:develop-runtime-certificate -- \\
    --verify --environment=xrteeth-develop \\
    --raw=<absolute-owner-0600-json-path-inside-this-repository> \\
    --deployment-evidence=<absolute-owner-0600-json-path-inside-this-repository> \\
    --physical-probe=<absolute-owner-0600-json-path-inside-this-repository> \\
    --trust-policy=<absolute-owner-0600-json-path-inside-this-repository> \\
    --certificate=<absolute-owner-0600-json-path-inside-this-repository> \\
    --closeout=<absolute-owner-0600-json-path-inside-this-repository>

Create first checks trusted current freshness, then historically replays the
signed raw full-range/v2 reconciliationInput at the two v4 attestations' shared
issuedAt. Verify intentionally performs only the signed historical replay, so a
valid issued certificate remains verifiable after its short attestation TTL.
Both modes are offline and read-only: no network, database, key, environment,
READY, Production, publish, main, or tmrpp action is available. Create writes
only a sanitized certificate and closeout, each once with O_EXCL and mode 0600.
`;

export const ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_CERTIFICATE_CLI_DIAGNOSTIC_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-runtime-verification-certificate-cli-diagnostic/v1" as const;

export interface OrganizationReconciliationDevelopRuntimeCertificateCliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export interface OrganizationReconciliationDevelopRuntimeCertificateCliRuntime {
  readonly repositoryRoot?: string;
  readonly now?: () => Date;
  readonly resolveTrustProfile?: (profileId: string) => OrganizationReconciliationTrustedProfile | undefined;
  readonly createCertificate?: (
    input: CreateOrganizationReconciliationDevelopRuntimeCertificateInput
  ) => OrganizationReconciliationDevelopRuntimeCertificateArtifacts;
  readonly verifyCertificate?: (
    input: VerifyOrganizationReconciliationDevelopRuntimeCertificateInput
  ) => OrganizationReconciliationDevelopRuntimeCertificateArtifacts;
}

type Action = "create" | "verify";

interface ParsedArguments {
  readonly action: Action;
  readonly rawPath: string;
  readonly deploymentEvidencePath: string;
  readonly physicalProbePath: string;
  readonly trustPolicyPath: string;
  readonly certificatePath: string;
  readonly closeoutPath: string;
}

class RuntimeCertificateCliError extends Error {
  constructor(readonly failureId:
    | "invalid-arguments"
    | "invalid-input-path"
    | "invalid-output-path"
    | "trust-profile-not-provisioned"
    | "artifact-read-failed"
    | "artifact-write-failed"
    | "create-failed"
    | "verify-failed") {
    super(failureId);
    this.name = "RuntimeCertificateCliError";
  }
}

export async function runOrganizationReconciliationDevelopRuntimeCertificateCli(
  argv: readonly string[],
  io: OrganizationReconciliationDevelopRuntimeCertificateCliIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  },
  runtime: OrganizationReconciliationDevelopRuntimeCertificateCliRuntime = {}
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationDevelopRuntimeCertificateHelp);
    return 0;
  }

  let parsed: ParsedArguments;
  let repositoryRoot: string;
  try {
    parsed = parseArguments(argv);
    repositoryRoot = await validateRepositoryRoot(runtime.repositoryRoot ?? process.cwd());
    for (const path of [
      parsed.rawPath, parsed.deploymentEvidencePath, parsed.physicalProbePath,
      parsed.trustPolicyPath, parsed.certificatePath, parsed.closeoutPath
    ]) validateLexicalJsonPath(path, repositoryRoot);
    if (new Set([
      parsed.rawPath, parsed.deploymentEvidencePath, parsed.physicalProbePath,
      parsed.trustPolicyPath, parsed.certificatePath, parsed.closeoutPath
    ]).size !== 6) throw new RuntimeCertificateCliError("invalid-arguments");
    if (parsed.action === "create") {
      await Promise.all([
        assertMissingOutputPath(parsed.certificatePath, repositoryRoot),
        assertMissingOutputPath(parsed.closeoutPath, repositoryRoot)
      ]);
    }
  } catch (error) {
    const failure = error instanceof RuntimeCertificateCliError ? error.failureId : "invalid-arguments";
    diagnostic(io, argv.includes("--verify") ? "verify" : "create", failure);
    return 2;
  }

  try {
    const [rawArtifactBytes, deploymentEvidenceBytes, physicalProbeBytes, trustPolicyBytes] =
      await Promise.all([
        readOrdinaryOwner0600File(parsed.rawPath, repositoryRoot, MAX_RAW_ARTIFACT_BYTES),
        readOrdinaryOwner0600File(
          parsed.deploymentEvidencePath,
          repositoryRoot,
          MAX_PUBLIC_ARTIFACT_BYTES
        ),
        readOrdinaryOwner0600File(parsed.physicalProbePath, repositoryRoot, MAX_PUBLIC_ARTIFACT_BYTES),
        readOrdinaryOwner0600File(parsed.trustPolicyPath, repositoryRoot, MAX_PUBLIC_ARTIFACT_BYTES)
      ]);
    const policy = parseOrganizationReconciliationTrustPolicy(
      JSON.parse(trustPolicyBytes.toString("utf8")) as unknown
    );
    const profile = (runtime.resolveTrustProfile ?? resolveCompiledOrganizationReconciliationTrustProfile)(
      policy.profileId
    );
    if (!profile) throw new RuntimeCertificateCliError("trust-profile-not-provisioned");
    const common = Object.freeze({
      rawArtifactBytes,
      deploymentEvidenceBytes,
      physicalProbeBytes,
      trustPolicyBytes,
      trustedProfile: profile
    });

    let artifacts: OrganizationReconciliationDevelopRuntimeCertificateArtifacts;
    if (parsed.action === "create") {
      const now = readTrustedCurrentTime(runtime.now ?? (() => new Date()));
      artifacts = (runtime.createCertificate ??
        createOrganizationReconciliationDevelopRuntimeCertificate)({ ...common, now });
      const certificatePayload = serializeOrganizationReconciliationDevelopRuntimeCertificate(
        artifacts.certificate
      );
      const closeoutPayload = serializeOrganizationReconciliationDevelopRuntimeCloseout(
        artifacts.closeout,
        artifacts.certificate
      );
      await writeExclusiveOutputPair(
        parsed.certificatePath,
        certificatePayload,
        parsed.closeoutPath,
        closeoutPayload,
        repositoryRoot
      );
    } else {
      const [certificateBytes, closeoutBytes] = await Promise.all([
        readOrdinaryOwner0600File(parsed.certificatePath, repositoryRoot, MAX_PUBLIC_ARTIFACT_BYTES),
        readOrdinaryOwner0600File(parsed.closeoutPath, repositoryRoot, MAX_PUBLIC_ARTIFACT_BYTES)
      ]);
      artifacts = (runtime.verifyCertificate ??
        verifyOrganizationReconciliationDevelopRuntimeCertificate)({
        ...common,
        certificateBytes,
        closeoutBytes
      });
    }
    io.stdout(`${JSON.stringify({
      status: parsed.action === "create" ? "created" : "verified",
      certificateSha256: artifacts.certificate.certificateSha256,
      authoritativeCertificateSha256: artifacts.closeout.authoritativeCertificateSha256,
      closeoutSha256: artifacts.closeout.closeoutSha256
    })}\n`);
    return 0;
  } catch (error) {
    const failure = error instanceof RuntimeCertificateCliError
      ? error.failureId
      : error instanceof OrganizationReconciliationDevelopRuntimeCertificateError
        ? error.failureId
        : parsed.action === "create" ? "create-failed" : "verify-failed";
    diagnostic(io, parsed.action, failure);
    return failure === "artifact-read-failed" || failure === "artifact-write-failed" ? 2 : 1;
  }
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  if (!Array.isArray(argv) || argv.length !== 8) throw new RuntimeCertificateCliError("invalid-arguments");
  const createCount = argv.filter((argument) => argument === "--create").length;
  const verifyCount = argv.filter((argument) => argument === "--verify").length;
  if (createCount + verifyCount !== 1) throw new RuntimeCertificateCliError("invalid-arguments");
  const values = new Map<string, string>();
  for (const argument of argv) {
    if (argument === "--create" || argument === "--verify") continue;
    if (typeof argument !== "string") throw new RuntimeCertificateCliError("invalid-arguments");
    const separator = argument.indexOf("=");
    if (separator < 3) throw new RuntimeCertificateCliError("invalid-arguments");
    const key = argument.slice(0, separator);
    const value = argument.slice(separator + 1);
    if (values.has(key) || value.length < 1) throw new RuntimeCertificateCliError("invalid-arguments");
    values.set(key, value);
  }
  if (values.size !== 7 || values.get("--environment") !== "xrteeth-develop") {
    throw new RuntimeCertificateCliError("invalid-arguments");
  }
  for (const key of [
    "--raw", "--deployment-evidence", "--physical-probe", "--trust-policy",
    "--certificate", "--closeout"
  ]) if (!values.has(key)) throw new RuntimeCertificateCliError("invalid-arguments");
  return Object.freeze({
    action: createCount === 1 ? "create" : "verify",
    rawPath: values.get("--raw")!,
    deploymentEvidencePath: values.get("--deployment-evidence")!,
    physicalProbePath: values.get("--physical-probe")!,
    trustPolicyPath: values.get("--trust-policy")!,
    certificatePath: values.get("--certificate")!,
    closeoutPath: values.get("--closeout")!
  });
}

async function validateRepositoryRoot(candidate: string): Promise<string> {
  if (typeof candidate !== "string" || !isAbsolute(candidate) || resolve(candidate) !== candidate ||
    candidate.length < 2 || candidate.length > 4_096 || candidate.includes("\0")) {
    throw new RuntimeCertificateCliError("invalid-arguments");
  }
  const stat = await lstat(candidate);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new RuntimeCertificateCliError("invalid-arguments");
  return candidate;
}

function validateLexicalJsonPath(path: string, repositoryRoot: string): void {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0") ||
    path.length < 2 || path.length > 4_096 || extname(path) !== ".json" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$/.test(basename(path))) {
    throw new RuntimeCertificateCliError("invalid-input-path");
  }
  const scoped = relative(repositoryRoot, path);
  if (scoped.length < 1 || scoped === ".." || scoped.startsWith(`..${separator()}`) || isAbsolute(scoped)) {
    throw new RuntimeCertificateCliError("invalid-input-path");
  }
}

async function readOrdinaryOwner0600File(
  path: string,
  repositoryRoot: string,
  maximumBytes: number
): Promise<Buffer> {
  validateLexicalJsonPath(path, repositoryRoot);
  const flags = fsConstants.O_RDONLY |
    (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0) |
    (typeof fsConstants.O_NONBLOCK === "number" ? fsConstants.O_NONBLOCK : 0);
  let handle: FileHandle | null = null;
  try {
    const before = await lstat(path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
      (before.mode & 0o777n) !== 0o600n || before.size < 2n || before.size > BigInt(maximumBytes) ||
      (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))) {
      throw new RuntimeCertificateCliError("artifact-read-failed");
    }
    await assertRealPathInsideRepository(path, repositoryRoot);
    handle = await open(path, flags);
    const opened = await handle.stat({ bigint: true });
    if (!sameOpenedFile(before, opened)) throw new RuntimeCertificateCliError("artifact-read-failed");
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (bytes.byteLength !== Number(before.size) || !sameOpenedFile(before, after) ||
      before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      bytes.fill(0);
      throw new RuntimeCertificateCliError("artifact-read-failed");
    }
    return bytes;
  } catch (error) {
    if (error instanceof RuntimeCertificateCliError) throw error;
    throw new RuntimeCertificateCliError("artifact-read-failed");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function sameOpenedFile(
  expected: BigIntStats,
  actual: BigIntStats
): boolean {
  return actual.isFile() && actual.nlink === 1n && (actual.mode & 0o777n) === 0o600n &&
    actual.dev === expected.dev && actual.ino === expected.ino && actual.uid === expected.uid &&
    actual.size === expected.size;
}

async function assertRealPathInsideRepository(path: string, repositoryRoot: string): Promise<void> {
  const [rootReal, pathReal] = await Promise.all([realpath(repositoryRoot), realpath(path)]);
  const expected = resolve(rootReal, relative(repositoryRoot, path));
  if (pathReal !== expected) throw new RuntimeCertificateCliError("invalid-input-path");
}

async function assertMissingOutputPath(path: string, repositoryRoot: string): Promise<void> {
  validateLexicalJsonPath(path, repositoryRoot);
  const parent = dirname(path);
  try {
    const parentStat = await lstat(parent);
    if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) {
      throw new RuntimeCertificateCliError("invalid-output-path");
    }
    const [rootReal, parentReal] = await Promise.all([realpath(repositoryRoot), realpath(parent)]);
    const expected = resolve(rootReal, relative(repositoryRoot, parent));
    if (parentReal !== expected) throw new RuntimeCertificateCliError("invalid-output-path");
  } catch (error) {
    if (error instanceof RuntimeCertificateCliError) throw error;
    throw new RuntimeCertificateCliError("invalid-output-path");
  }
  try {
    await lstat(path);
    throw new RuntimeCertificateCliError("invalid-output-path");
  } catch (error) {
    if (error instanceof RuntimeCertificateCliError) throw error;
    if (!isMissing(error)) throw new RuntimeCertificateCliError("invalid-output-path");
  }
}

interface CreatedOutput {
  readonly path: string;
  readonly handle: FileHandle;
  readonly dev: bigint;
  readonly ino: bigint;
}

async function writeExclusiveOutputPair(
  certificatePath: string,
  certificatePayload: string,
  closeoutPath: string,
  closeoutPayload: string,
  repositoryRoot: string
): Promise<void> {
  if (!validOutputPayload(certificatePayload) || !validOutputPayload(closeoutPayload)) {
    throw new RuntimeCertificateCliError("artifact-write-failed");
  }
  await Promise.all([
    assertMissingOutputPath(certificatePath, repositoryRoot),
    assertMissingOutputPath(closeoutPath, repositoryRoot)
  ]);
  const created: CreatedOutput[] = [];
  try {
    created.push(await createExclusiveOutput(certificatePath));
    created.push(await createExclusiveOutput(closeoutPath));
    await created[0]!.handle.writeFile(certificatePayload, "utf8");
    await created[1]!.handle.writeFile(closeoutPayload, "utf8");
    await Promise.all(created.map((output) => output.handle.sync()));
    for (const output of created) {
      const stat = await output.handle.stat({ bigint: true });
      if (!stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o777n) !== 0o600n ||
        stat.dev !== output.dev || stat.ino !== output.ino || stat.uid !== BigInt(process.getuid?.() ?? stat.uid)) {
        throw new RuntimeCertificateCliError("artifact-write-failed");
      }
    }
  } catch (error) {
    await Promise.allSettled(created.map((output) => output.handle.close()));
    await Promise.allSettled(created.map((output) => removeCreatedOutput(output)));
    if (error instanceof RuntimeCertificateCliError) throw error;
    throw new RuntimeCertificateCliError("artifact-write-failed");
  }
  await Promise.all(created.map((output) => output.handle.close()));
}

async function createExclusiveOutput(path: string): Promise<CreatedOutput> {
  const flags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY |
    (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0) |
    (typeof fsConstants.O_NONBLOCK === "number" ? fsConstants.O_NONBLOCK : 0);
  const handle = await open(path, flags, 0o600);
  let identity: Readonly<{ dev: bigint; ino: bigint }> | null = null;
  try {
    const initial = await handle.stat({ bigint: true });
    identity = Object.freeze({ dev: initial.dev, ino: initial.ino });
    await handle.chmod(0o600);
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o777n) !== 0o600n ||
      (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid()))) {
      throw new RuntimeCertificateCliError("artifact-write-failed");
    }
    return Object.freeze({ path, handle, dev: stat.dev, ino: stat.ino });
  } catch (error) {
    await handle.close().catch(() => undefined);
    if (identity !== null) {
      await removeCreatedOutput({ path, handle, dev: identity.dev, ino: identity.ino });
    }
    throw error;
  }
}

async function removeCreatedOutput(output: CreatedOutput): Promise<void> {
  try {
    const stat = await lstat(output.path, { bigint: true });
    if (stat.isFile() && !stat.isSymbolicLink() && stat.dev === output.dev && stat.ino === output.ino) {
      await unlink(output.path);
    }
  } catch {
    // Best-effort rollback is limited to the exact inode created by this process.
  }
}

function validOutputPayload(payload: string): boolean {
  const bytes = Buffer.byteLength(payload, "utf8");
  return typeof payload === "string" && payload.endsWith("\n") && bytes >= 3 &&
    bytes <= MAX_PUBLIC_ARTIFACT_BYTES;
}

function readTrustedCurrentTime(now: () => Date): Date {
  let value: unknown;
  try {
    value = now.call(undefined);
  } catch {
    throw new RuntimeCertificateCliError("create-failed");
  }
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new RuntimeCertificateCliError("create-failed");
  }
  return new Date(value.getTime());
}

function diagnostic(
  io: OrganizationReconciliationDevelopRuntimeCertificateCliIo,
  action: Action,
  failure: string
): void {
  io.stderr(`${JSON.stringify({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_CERTIFICATE_CLI_DIAGNOSTIC_CONTRACT,
    environment: "xrteeth-develop",
    mode: "read-only",
    action,
    status: "failed",
    failure
  })}\n`);
}

function isMissing(error: unknown): boolean {
  return error !== null && typeof error === "object" && "code" in error &&
    (error as { readonly code?: unknown }).code === "ENOENT";
}

function separator(): string {
  return process.platform === "win32" ? "\\" : "/";
}

async function main(): Promise<void> {
  process.exitCode = await runOrganizationReconciliationDevelopRuntimeCertificateCli(
    process.argv.slice(2)
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
