import { createHash } from "node:crypto";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import { lstat, open, realpath, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  resolveSoleCompiledOrganizationReconciliationTrustBinding,
  serializeOrganizationReconciliationCompiledTrustPolicy,
  type OrganizationReconciliationCompiledTrustBinding
} from "../apps/identity-adapter/src/iam-organization-reconciliation-trust-profiles.js";

const ENVIRONMENT = "xrteeth-develop" as const;
const MAX_POLICY_BYTES = 128 * 1024;

export const organizationReconciliationEmitCompiledTrustPolicyHelp = `Usage:
  npm --silent run iam:organization-reconciliation:emit-compiled-trust-policy -- \\
    --output=<absolute-new-json-path>

Emits the exact canonical public trust policy compiled into this immutable
Develop build. The production registry must contain exactly one internally
consistent template-derived policy/profile pair. The output is created once
with O_EXCL and owner-only mode 0600 and contains only public Ed25519 SPKI
material. There is no profile, revision, collector, key/pin, environment,
private-key, network, database, READY, Production, publish, main, or tmrpp
override.
`;

export const ORGANIZATION_RECONCILIATION_EMIT_COMPILED_TRUST_POLICY_DIAGNOSTIC_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-emit-compiled-trust-policy-diagnostic/v1" as const;

export interface OrganizationReconciliationEmitCompiledTrustPolicyIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export interface OrganizationReconciliationEmitCompiledTrustPolicyRuntime {
  /** Explicit test seam; the executable always uses the immutable production resolver. */
  readonly resolveCompiledBinding?: () => OrganizationReconciliationCompiledTrustBinding | undefined;
}

class EmitCompiledTrustPolicyError extends Error {
  constructor(readonly failureId:
    | "invalid-arguments"
    | "trust-profile-not-provisioned"
    | "trust-profile-mismatch"
    | "output-path-invalid"
    | "output-write-failed") {
    super(failureId);
    this.name = "EmitCompiledTrustPolicyError";
  }
}

export async function runOrganizationReconciliationEmitCompiledTrustPolicyCli(
  argv: readonly string[],
  io: OrganizationReconciliationEmitCompiledTrustPolicyIo = {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text)
  },
  runtime: OrganizationReconciliationEmitCompiledTrustPolicyRuntime = {}
): Promise<number> {
  if (argv.length === 1 && argv[0] === "--help") {
    io.stdout(organizationReconciliationEmitCompiledTrustPolicyHelp);
    return 0;
  }

  let outputPath: string;
  try {
    outputPath = parseArguments(argv);
  } catch {
    diagnostic(io, "invalid-arguments");
    return 2;
  }

  let binding: OrganizationReconciliationCompiledTrustBinding;
  let payload: string;
  try {
    const resolved = (runtime.resolveCompiledBinding ??
      resolveSoleCompiledOrganizationReconciliationTrustBinding)();
    if (!resolved) throw new EmitCompiledTrustPolicyError("trust-profile-not-provisioned");
    if (resolved.policy.environment !== ENVIRONMENT || resolved.profile.expectedEnvironment !== ENVIRONMENT) {
      throw new EmitCompiledTrustPolicyError("trust-profile-mismatch");
    }
    binding = resolved;
    try {
      payload = serializeOrganizationReconciliationCompiledTrustPolicy(binding);
    } catch {
      throw new EmitCompiledTrustPolicyError("trust-profile-mismatch");
    }
    const bytes = Buffer.byteLength(payload, "utf8");
    if (!payload.endsWith("\n") || bytes < 3 || bytes > MAX_POLICY_BYTES) {
      throw new EmitCompiledTrustPolicyError("trust-profile-mismatch");
    }
  } catch (error) {
    const failure = error instanceof EmitCompiledTrustPolicyError
      ? error.failureId
      : "trust-profile-mismatch";
    diagnostic(io, failure);
    return 1;
  }

  try {
    validateOutputPath(outputPath);
    await writeExclusiveOwner0600(outputPath, payload);
  } catch (error) {
    const failure = error instanceof EmitCompiledTrustPolicyError
      ? error.failureId
      : "output-write-failed";
    diagnostic(io, failure);
    return 2;
  }

  io.stdout(`${JSON.stringify({
    status: "emitted",
    policySha256: createHash("sha256").update(payload.slice(0, -1), "utf8").digest("hex")
  })}\n`);
  return 0;
}

function parseArguments(argv: readonly string[]): string {
  if (!Array.isArray(argv) || argv.length !== 1 || typeof argv[0] !== "string") {
    throw new EmitCompiledTrustPolicyError("invalid-arguments");
  }
  const prefix = "--output=";
  if (!argv[0].startsWith(prefix) || argv[0].length === prefix.length) {
    throw new EmitCompiledTrustPolicyError("invalid-arguments");
  }
  return argv[0].slice(prefix.length);
}

function validateOutputPath(path: string): void {
  if (
    !isAbsolute(path) || resolve(path) !== path || path.includes("\0") ||
    path.length < 2 || path.length > 4_096 || extname(path) !== ".json" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json$/.test(basename(path))
  ) throw new EmitCompiledTrustPolicyError("output-path-invalid");
}

async function writeExclusiveOwner0600(path: string, payload: string): Promise<void> {
  validateOutputPath(path);
  if (
    typeof process.getuid !== "function" || typeof fsConstants.O_NOFOLLOW !== "number" ||
    typeof fsConstants.O_NONBLOCK !== "number"
  ) throw new EmitCompiledTrustPolicyError("output-write-failed");
  const parent = dirname(path);
  try {
    const [parentStat, parentReal] = await Promise.all([lstat(parent, { bigint: true }), realpath(parent)]);
    if (
      !parentStat.isDirectory() || parentStat.isSymbolicLink() || parentReal !== parent ||
      parentStat.uid !== BigInt(process.getuid())
    ) throw new EmitCompiledTrustPolicyError("output-path-invalid");
  } catch (error) {
    if (error instanceof EmitCompiledTrustPolicyError) throw error;
    throw new EmitCompiledTrustPolicyError("output-path-invalid");
  }

  const flags = fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY |
    fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
  let handle: FileHandle | null = null;
  let created: { readonly dev: bigint; readonly ino: bigint } | null = null;
  try {
    handle = await open(path, flags, 0o600);
    await handle.chmod(0o600);
    const before = await handle.stat({ bigint: true });
    assertCreatedOutput(before);
    created = Object.freeze({ dev: before.dev, ino: before.ino });
    await handle.writeFile(payload, "utf8");
    await handle.sync();
    const after = await handle.stat({ bigint: true });
    assertCreatedOutput(after);
    if (
      before.dev !== after.dev || before.ino !== after.ino ||
      after.size !== BigInt(Buffer.byteLength(payload, "utf8"))
    ) throw new EmitCompiledTrustPolicyError("output-write-failed");
    const [pathStat, parentReal] = await Promise.all([lstat(path, { bigint: true }), realpath(parent)]);
    if (
      parentReal !== parent || !sameCreatedOutput(after, pathStat) || pathStat.isSymbolicLink()
    ) throw new EmitCompiledTrustPolicyError("output-write-failed");
  } catch (error) {
    await handle?.close().catch(() => undefined);
    handle = null;
    if (created) await removeExactCreatedOutput(path, created);
    if (error instanceof EmitCompiledTrustPolicyError) throw error;
    throw new EmitCompiledTrustPolicyError("output-write-failed");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function assertCreatedOutput(stat: BigIntStats): void {
  if (
    !stat.isFile() || stat.nlink !== 1n || (stat.mode & 0o777n) !== 0o600n ||
    stat.uid !== BigInt(process.getuid!())
  ) throw new EmitCompiledTrustPolicyError("output-write-failed");
}

function sameCreatedOutput(expected: BigIntStats, actual: BigIntStats): boolean {
  return actual.isFile() && actual.nlink === 1n && (actual.mode & 0o777n) === 0o600n &&
    actual.uid === expected.uid && actual.dev === expected.dev && actual.ino === expected.ino &&
    actual.size === expected.size;
}

async function removeExactCreatedOutput(
  path: string,
  created: { readonly dev: bigint; readonly ino: bigint }
): Promise<void> {
  try {
    const stat = await lstat(path, { bigint: true });
    if (
      stat.isFile() && !stat.isSymbolicLink() && stat.dev === created.dev && stat.ino === created.ino
    ) await unlink(path);
  } catch {
    // Best-effort rollback is limited to the exact inode created by this process.
  }
}

function diagnostic(
  io: OrganizationReconciliationEmitCompiledTrustPolicyIo,
  failure: string
): void {
  io.stderr(`${JSON.stringify({
    contract: ORGANIZATION_RECONCILIATION_EMIT_COMPILED_TRUST_POLICY_DIAGNOSTIC_CONTRACT,
    environment: ENVIRONMENT,
    mode: "read-only",
    status: "failed",
    failure
  })}\n`);
}

async function main(): Promise<void> {
  process.exitCode = await runOrganizationReconciliationEmitCompiledTrustPolicyCli(
    process.argv.slice(2)
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
