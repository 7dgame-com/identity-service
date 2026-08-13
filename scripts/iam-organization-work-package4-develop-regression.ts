import { constants as fsConstants } from "node:fs";
import { chmod, lstat, mkdtemp, open, readFile, realpath, rm, stat } from "node:fs/promises";
import { execFile } from "node:child_process";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import {
  ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT
} from "./iam-organization-work-package4-develop-completion-gate.js";

const execFileAsync = promisify(execFile);
const FULL_REVISION = /^[a-f0-9]{40}$/;
const MAX_REPORT_BYTES = 64 * 1024 * 1024;
export const ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES = Object.freeze([
  "iam-organization-identity-native.spec.ts",
  "iam-organization-identity-native-window-gate.spec.ts",
  "plugin-user-primary-read-organization-native.spec.ts",
  "iam-organization-reconciliation-develop-full-pipeline.spec.ts",
  "iam-organization-reconciliation-develop-plugin-campus-surfaces.spec.ts",
  "identity-adapter.spec.ts"
] as const);

interface VitestJsonReport {
  readonly numTotalTests: number;
  readonly numPassedTests: number;
  readonly numFailedTests: number;
  readonly numPendingTests: number;
  readonly success: boolean;
  readonly testResults: readonly { readonly name: string; readonly status: string }[];
}

export interface DevelopRegressionSummary {
  readonly contract: typeof ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly buildRevision: string;
  readonly success: true;
  readonly passedTests: number;
  readonly failedTests: 0;
  readonly skippedTests: number;
  readonly totalTests: number;
  readonly requiredTestFiles: readonly string[];
}

export function createOrganizationWorkPackage4DevelopRegressionSummary(
  candidate: unknown,
  buildRevision: string,
  repositoryRoot: string
): DevelopRegressionSummary {
  if (!FULL_REVISION.test(buildRevision)) throw new Error("build-revision-invalid");
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) throw new Error("vitest-report-invalid");
  const report = candidate as Partial<VitestJsonReport>;
  for (const name of ["numTotalTests", "numPassedTests", "numFailedTests", "numPendingTests"] as const) {
    if (!Number.isSafeInteger(report[name]) || (report[name] as number) < 0) throw new Error("vitest-report-invalid");
  }
  if (report.success !== true || report.numFailedTests !== 0 || report.numPassedTests! < 900 ||
      report.numTotalTests !== report.numPassedTests! + report.numFailedTests! + report.numPendingTests!) {
    throw new Error("regression-suite-not-passed");
  }
  if (!Array.isArray(report.testResults) || report.testResults.some((result) =>
    !result || typeof result !== "object" || typeof result.name !== "string" || result.status !== "passed")) {
    throw new Error("vitest-results-invalid");
  }
  const root = resolve(repositoryRoot);
  const passedFiles = new Set(report.testResults.map((result) => {
    const path = resolve(result.name);
    const rel = relative(root, path);
    if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error("vitest-result-path-invalid");
    return rel.split("/").at(-1)!;
  }));
  if (ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES.some((name) => !passedFiles.has(name))) {
    throw new Error("required-regression-test-missing");
  }
  return Object.freeze({
    contract: ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT,
    environment: "xrteeth-develop",
    buildRevision,
    success: true,
    passedTests: report.numPassedTests!,
    failedTests: 0,
    skippedTests: report.numPendingTests!,
    totalTests: report.numTotalTests!,
    requiredTestFiles: Object.freeze([...ORGANIZATION_WORK_PACKAGE4_DEVELOP_REQUIRED_TEST_FILES])
  });
}

export async function runOrganizationWorkPackage4DevelopRegression(input: {
  readonly repositoryRoot: string;
  readonly expectedRevision: string;
  readonly outputPath: string;
}): Promise<DevelopRegressionSummary> {
  const root = await realpath(resolve(input.repositoryRoot));
  if (!FULL_REVISION.test(input.expectedRevision) || !isAbsolute(input.outputPath)) throw new Error("invalid-input");
  const outputPath = resolve(input.outputPath);
  if (dirname(outputPath) !== await realpath(dirname(outputPath))) throw new Error("output-parent-invalid");
  const [{ stdout: revision }, { stdout: dirty }] = await Promise.all([
    execFileAsync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", maxBuffer: 1024 }),
    execFileAsync("git", ["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude)node_modules"], {
      cwd: root, encoding: "utf8", maxBuffer: 1024 * 1024
    })
  ]);
  const actualRevision = revision.trim();
  if (actualRevision !== input.expectedRevision) throw new Error("revision-mismatch");
  if (dirty.length !== 0) throw new Error("tracked-worktree-not-clean");

  const tempRoot = await realpath(await mkdtemp(join(tmpdir(), "iam-wp4-regression-")));
  await chmod(tempRoot, 0o700);
  const reportPath = join(tempRoot, "vitest-report.json");
  try {
    await execFileAsync(process.execPath, [
      join(root, "node_modules", "vitest", "vitest.mjs"), "run", "--reporter=json", `--outputFile=${reportPath}`
    ], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    const info = await stat(reportPath);
    if (!info.isFile() || info.size < 2 || info.size > MAX_REPORT_BYTES) throw new Error("vitest-report-file-invalid");
    const summary = createOrganizationWorkPackage4DevelopRegressionSummary(
      JSON.parse(await readFile(reportPath, "utf8")), actualRevision, root
    );
    await writeExclusive0600(outputPath, Buffer.from(`${JSON.stringify(summary)}\n`));
    return summary;
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

async function writeExclusive0600(path: string, bytes: Buffer): Promise<void> {
  if (typeof fsConstants.O_NOFOLLOW !== "number") throw new Error("unsupported-platform");
  let handle;
  let createdIdentity: { dev: number; ino: number } | null = null;
  try {
    handle = await open(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    const created = await handle.stat();
    createdIdentity = { dev: created.dev, ino: created.ino };
    await handle.writeFile(bytes);
    await handle.sync();
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || (opened.mode & 0o077) !== 0) throw new Error("output-file-invalid");
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    const current = await lstat(path).catch(() => null);
    if (createdIdentity && current?.isFile() && current.dev === createdIdentity.dev && current.ino === createdIdentity.ino) {
      await rm(path, { force: true });
    }
    throw error;
  }
  await handle.close();
}

async function main(): Promise<void> {
  const values = new Map(process.argv.slice(2).map((arg) => {
    const index = arg.indexOf("=");
    if (index < 1) throw new Error("Usage: --expected-revision=<full40> --output=<absolute-path>");
    return [arg.slice(0, index), arg.slice(index + 1)];
  }));
  if (values.size !== 2 || !values.has("--expected-revision") || !values.has("--output")) {
    throw new Error("Usage: --expected-revision=<full40> --output=<absolute-path>");
  }
  const summary = await runOrganizationWorkPackage4DevelopRegression({
    repositoryRoot: process.cwd(), expectedRevision: values.get("--expected-revision")!, outputPath: values.get("--output")!
  });
  process.stdout.write(`${JSON.stringify({ status: "completed", buildRevision: summary.buildRevision,
    passedTests: summary.passedTests, skippedTests: summary.skippedTests })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "regression-failed"}\n`);
    process.exitCode = 1;
  });
}
