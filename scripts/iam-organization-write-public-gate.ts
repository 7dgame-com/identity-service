import { pathToFileURL } from "node:url";
import { isAbsolute, resolve } from "node:path";
import { writeOrganizationEvidenceExclusive0600 } from "./iam-organization-write-evidence-output.js";

export interface OrganizationWritePublicGateOptions {
  urls: string[];
  expectedMode: "disabled" | "legacy-proxy" | "dual-write" | "identity-native";
  expectedRouteIntegration: boolean;
  expectedDualWriteExecution: boolean;
  expectedIdentityNativeExecution: boolean;
  expectedCandidateMaterializationEnabled: boolean;
  expectedCandidateMaterializationTargetConfigured: boolean;
  expectedCandidateBatchMaterializationEnabled: boolean;
  expectedCandidateBatchMaterializationEnvironment: "disabled" | "xrteeth-develop";
  expectedRecoveryDrillEnabled: boolean;
  expectedRecoveryDrillTargetConfigured: boolean;
  expectedRolloutMode: "off" | "allowlist" | "percentage" | "full";
  expectedRolloutPercentage: number;
  expectedAllowlistCount?: number;
  expectedRevision?: string;
  outputPath?: string;
}

interface OrganizationWritePosture {
  mode: string;
  routeIntegrationEnabled: boolean;
  dualWriteExecutionEnabled: boolean;
  identityNativeExecutionEnabled: boolean;
  candidateMaterializationEnabled: boolean;
  candidateMaterializationTargetConfigured: boolean;
  candidateBatchMaterializationEnabled: boolean;
  candidateBatchMaterializationEnvironment: string;
  recoveryDrillEnabled: boolean;
  recoveryDrillTargetConfigured: boolean;
  rolloutMode: string;
  rolloutAllowlistCount: number;
  rolloutPercentage: number;
  sourceOfTruth: string;
  identityNativeSupported: boolean;
}

export const ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT = "iam-organization-write-public-gate/v1" as const;

async function main(): Promise<void> {
  const options = parseOrganizationWritePublicGateArgs(process.argv.slice(2));
  const result = await runOrganizationWritePublicGate(options);
  if (options.outputPath) {
    const written = await writeOrganizationEvidenceExclusive0600(options.outputPath, result);
    process.stdout.write(`${JSON.stringify({ status: result.passed ? "completed" : "blocked", sha256: written.sha256 })}\n`);
  } else process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.passed) process.exitCode = 1;
}

export async function runOrganizationWritePublicGate(
  options: OrganizationWritePublicGateOptions,
  fetcher: typeof fetch = fetch
) {
  const results = await Promise.all(options.urls.map((url) => inspect(fetcher, url, options)));
  const failures = results.flatMap((result) => result.failures.map((failure) => `${result.url}: ${failure}`));
  return { contract: ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT, passed: failures.length === 0, results, failures };
}

async function inspect(fetcher: typeof fetch, url: string, options: OrganizationWritePublicGateOptions) {
  const response = await fetcher(url, { signal: AbortSignal.timeout(10_000) });
  const body = await response.json() as Record<string, any>;
  const posture = body.capabilities?.organizationWrite as OrganizationWritePosture | undefined;
  const failures: string[] = [];

  if (!response.ok) failures.push(`HTTP ${response.status}`);
  if (body.status !== "ok" || body.service !== "identity-adapter") failures.push("identity health is not ok");
  if (options.expectedRevision !== undefined) compare(failures, "revision", body.revision, options.expectedRevision);
  if (!posture) {
    failures.push("capabilities.organizationWrite is missing; deploy a compatible identity-service image first");
  } else {
    compare(failures, "mode", posture.mode, options.expectedMode);
    compare(failures, "routeIntegrationEnabled", posture.routeIntegrationEnabled, options.expectedRouteIntegration);
    compare(failures, "dualWriteExecutionEnabled", posture.dualWriteExecutionEnabled, options.expectedDualWriteExecution);
    compare(failures, "identityNativeExecutionEnabled", posture.identityNativeExecutionEnabled, options.expectedIdentityNativeExecution);
    compare(
      failures,
      "candidateMaterializationEnabled",
      posture.candidateMaterializationEnabled,
      options.expectedCandidateMaterializationEnabled
    );
    compare(
      failures,
      "candidateMaterializationTargetConfigured",
      posture.candidateMaterializationTargetConfigured,
      options.expectedCandidateMaterializationTargetConfigured
    );
    compare(
      failures,
      "candidateBatchMaterializationEnabled",
      posture.candidateBatchMaterializationEnabled,
      options.expectedCandidateBatchMaterializationEnabled
    );
    compare(
      failures,
      "candidateBatchMaterializationEnvironment",
      posture.candidateBatchMaterializationEnvironment,
      options.expectedCandidateBatchMaterializationEnvironment
    );
    compare(failures, "recoveryDrillEnabled", posture.recoveryDrillEnabled, options.expectedRecoveryDrillEnabled);
    compare(
      failures,
      "recoveryDrillTargetConfigured",
      posture.recoveryDrillTargetConfigured,
      options.expectedRecoveryDrillTargetConfigured
    );
    compare(failures, "rolloutMode", posture.rolloutMode, options.expectedRolloutMode);
    compare(failures, "rolloutPercentage", posture.rolloutPercentage, options.expectedRolloutPercentage);
    if (options.expectedAllowlistCount !== undefined) {
      compare(failures, "rolloutAllowlistCount", posture.rolloutAllowlistCount, options.expectedAllowlistCount);
    }
    compare(failures, "sourceOfTruth", posture.sourceOfTruth,
      options.expectedMode === "identity-native" ? "identity-candidate-selected-legacy-unselected" : "legacy");
    compare(failures, "identityNativeSupported", posture.identityNativeSupported, options.expectedMode === "identity-native");
  }

  return { url, status: response.status, revision: body.revision ?? null, posture: posture ?? null, failures };
}

function compare(failures: string[], field: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) failures.push(`${field} expected ${String(expected)}, got ${String(actual)}`);
}

export function parseOrganizationWritePublicGateArgs(argv: string[]): OrganizationWritePublicGateOptions {
  const options: OrganizationWritePublicGateOptions = {
    urls: ["https://identity.d.xrteeth.com/health", "https://identity.d.tmrpp.com/health"],
    expectedMode: "disabled",
    expectedRouteIntegration: false,
    expectedDualWriteExecution: false,
    expectedIdentityNativeExecution: false,
    expectedCandidateMaterializationEnabled: false,
    expectedCandidateMaterializationTargetConfigured: false,
    expectedCandidateBatchMaterializationEnabled: false,
    expectedCandidateBatchMaterializationEnvironment: "disabled",
    expectedRecoveryDrillEnabled: false,
    expectedRecoveryDrillTargetConfigured: false,
    expectedRolloutMode: "off",
    expectedRolloutPercentage: 0,
    expectedAllowlistCount: 0
  };

  for (const arg of argv) {
    if (arg.startsWith("--urls=")) options.urls = csv(arg.slice("--urls=".length));
    else if (arg.startsWith("--expected-mode=")) options.expectedMode = enumValue(arg, "--expected-mode=", ["disabled", "legacy-proxy", "dual-write", "identity-native"]);
    else if (arg.startsWith("--expected-route-integration=")) options.expectedRouteIntegration = booleanValue(arg, "--expected-route-integration=");
    else if (arg.startsWith("--expected-dual-write-execution=")) options.expectedDualWriteExecution = booleanValue(arg, "--expected-dual-write-execution=");
    else if (arg.startsWith("--expected-identity-native-execution=")) options.expectedIdentityNativeExecution = booleanValue(arg, "--expected-identity-native-execution=");
    else if (arg.startsWith("--expected-candidate-materialization-enabled=")) {
      options.expectedCandidateMaterializationEnabled = booleanValue(arg, "--expected-candidate-materialization-enabled=");
    } else if (arg.startsWith("--expected-candidate-materialization-target-configured=")) {
      options.expectedCandidateMaterializationTargetConfigured = booleanValue(
        arg,
        "--expected-candidate-materialization-target-configured="
      );
    } else if (arg.startsWith("--expected-candidate-batch-materialization-enabled=")) {
      options.expectedCandidateBatchMaterializationEnabled = booleanValue(
        arg,
        "--expected-candidate-batch-materialization-enabled="
      );
    } else if (arg.startsWith("--expected-candidate-batch-materialization-environment=")) {
      options.expectedCandidateBatchMaterializationEnvironment = enumValue(
        arg,
        "--expected-candidate-batch-materialization-environment=",
        ["disabled", "xrteeth-develop"]
      );
    } else if (arg.startsWith("--expected-recovery-drill-enabled=")) {
      options.expectedRecoveryDrillEnabled = booleanValue(arg, "--expected-recovery-drill-enabled=");
    } else if (arg.startsWith("--expected-recovery-drill-target-configured=")) {
      options.expectedRecoveryDrillTargetConfigured = booleanValue(
        arg,
        "--expected-recovery-drill-target-configured="
      );
    } else if (arg.startsWith("--expected-rollout-mode=")) options.expectedRolloutMode = enumValue(arg, "--expected-rollout-mode=", ["off", "allowlist", "percentage", "full"]);
    else if (arg.startsWith("--expected-rollout-percentage=")) options.expectedRolloutPercentage = integerValue(arg, "--expected-rollout-percentage=", 0, 100);
    else if (arg.startsWith("--expected-allowlist-count=")) options.expectedAllowlistCount = integerValue(arg, "--expected-allowlist-count=", 0, 10_000);
    else if (arg === "--ignore-allowlist-count") options.expectedAllowlistCount = undefined;
    else if (arg.startsWith("--expected-revision=")) options.expectedRevision = revisionValue(arg.slice("--expected-revision=".length));
    else if (arg.startsWith("--output=")) options.outputPath = outputPathValue(arg.slice("--output=".length));
    else throw new Error(`Unknown argument: ${arg}`);
  }

  if (options.urls.length === 0) throw new Error("--urls must contain at least one health URL");
  return options;
}

function revisionValue(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(normalized)) throw new Error("--expected-revision must be a full 40-character Git SHA");
  return normalized;
}

function outputPathValue(value: string): string {
  if (!value || value.includes("\0") || !isAbsolute(value) || value !== resolve(value)) {
    throw new Error("--output must be a normalized absolute path");
  }
  return value;
}

function csv(value: string): string[] {
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

function enumValue<T extends string>(arg: string, prefix: string, values: readonly T[]): T {
  const value = arg.slice(prefix.length) as T;
  if (!values.includes(value)) throw new Error(`${prefix.slice(0, -1)} must be one of ${values.join(", ")}`);
  return value;
}

function booleanValue(arg: string, prefix: string): boolean {
  const value = arg.slice(prefix.length);
  if (value !== "true" && value !== "false") throw new Error(`${prefix.slice(0, -1)} must be true or false`);
  return value === "true";
}

function integerValue(arg: string, prefix: string, min: number, max: number): number {
  const value = Number(arg.slice(prefix.length));
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${prefix.slice(0, -1)} must be an integer from ${min} to ${max}`);
  return value;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
