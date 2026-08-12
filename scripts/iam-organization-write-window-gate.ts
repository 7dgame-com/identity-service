import { pathToFileURL } from "node:url";

export type OrganizationWriteWindowMode = "legacy-proxy" | "dual-write" | "identity-native";

export interface OrganizationWriteWindowGateOptions {
  adapterUrl: string;
  token: string | null;
  legacyUserId: number;
  expectedMode: OrganizationWriteWindowMode;
  expectedRevision?: string;
  expectedAllowlistCount: number;
  sinceMinutes: number;
  requireAlignment: boolean;
  expectedRecoveryDrill: boolean;
}

interface JsonResponse {
  status: number;
  body: Record<string, any>;
}

export async function runOrganizationWriteWindowGate(
  options: OrganizationWriteWindowGateOptions,
  fetcher: typeof fetch = fetch
) {
  if (!options.token) {
    throw new Error("IDENTITY_IAM_INTERNAL_API_TOKEN or IDENTITY_INTERNAL_API_TOKEN is required.");
  }

  const base = options.adapterUrl.replace(/\/$/, "");
  const headers = { "x-identity-internal-token": options.token };
  const [health, readinessResponse, decisionResponse, summaryResponse, recentResponse] = await Promise.all([
    getJson(fetcher, `${base}/health`),
    getJson(fetcher, `${base}/internal/iam/organization-write/readiness`, headers),
    getJson(fetcher, `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/decision`, headers),
    getJson(fetcher, `${base}/internal/iam/organization-write/operations/summary?sinceMinutes=${options.sinceMinutes}`, headers),
    getJson(fetcher, `${base}/internal/iam/organization-write/operations/recent?sinceMinutes=${options.sinceMinutes}&limit=50`, headers)
  ]);
  const alignmentResponse = options.requireAlignment
    ? await getJson(fetcher, `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/alignment`, headers)
    : null;
  const candidateResponse = options.expectedMode === "identity-native"
    ? await getJson(fetcher, `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/candidate`, headers)
    : null;

  const failures: string[] = [];
  const healthBody = health.body;
  const posture = healthBody.capabilities?.organizationWrite;
  const readiness = readinessResponse.body.data;
  const decision = decisionResponse.body.data;
  const summary = summaryResponse.body.data;
  const recent = recentResponse.body.data;
  const alignment = alignmentResponse?.body.data ?? null;
  const candidate = candidateResponse?.body.data ?? null;
  const expectedSource = options.expectedMode === "identity-native"
    ? "identity-candidate-selected-legacy-unselected"
    : "legacy";

  compare(failures, "health.status", healthBody.status, "ok");
  compare(failures, "health.service", healthBody.service, "identity-adapter");
  if (options.expectedRevision) compare(failures, "health.revision", healthBody.revision, options.expectedRevision);
  compare(failures, "health.organizationWrite.mode", posture?.mode, options.expectedMode);
  compare(failures, "health.organizationWrite.routeIntegrationEnabled", posture?.routeIntegrationEnabled, true);
  compare(failures, "health.organizationWrite.dualWriteExecutionEnabled", posture?.dualWriteExecutionEnabled, options.expectedMode === "dual-write");
  compare(failures, "health.organizationWrite.identityNativeExecutionEnabled", posture?.identityNativeExecutionEnabled, options.expectedMode === "identity-native");
  compare(failures, "health.organizationWrite.candidateMaterializationEnabled", posture?.candidateMaterializationEnabled, false);
  compare(
    failures,
    "health.organizationWrite.candidateMaterializationTargetConfigured",
    posture?.candidateMaterializationTargetConfigured,
    false
  );
  compare(
    failures,
    "health.organizationWrite.candidateBatchMaterializationEnabled",
    posture?.candidateBatchMaterializationEnabled,
    false
  );
  compare(
    failures,
    "health.organizationWrite.candidateBatchMaterializationEnvironment",
    posture?.candidateBatchMaterializationEnvironment,
    "disabled"
  );
  compare(
    failures,
    "health.organizationWrite.recoveryDrillEnabled",
    posture?.recoveryDrillEnabled,
    options.expectedRecoveryDrill
  );
  compare(
    failures,
    "health.organizationWrite.recoveryDrillTargetConfigured",
    posture?.recoveryDrillTargetConfigured,
    options.expectedRecoveryDrill
  );
  compare(failures, "health.organizationWrite.rolloutMode", posture?.rolloutMode, "allowlist");
  compare(failures, "health.organizationWrite.rolloutAllowlistCount", posture?.rolloutAllowlistCount, options.expectedAllowlistCount);
  compare(failures, "health.organizationWrite.rolloutPercentage", posture?.rolloutPercentage, 0);
  compare(failures, "health.organizationWrite.sourceOfTruth", posture?.sourceOfTruth, expectedSource);
  compare(failures, "health.organizationWrite.identityNativeSupported", posture?.identityNativeSupported, options.expectedMode === "identity-native");

  compare(failures, "readiness.mode", readiness?.mode, options.expectedMode);
  compare(failures, "readiness.routeIntegrationEnabled", readiness?.routeIntegrationEnabled, true);
  compare(failures, "readiness.route", readiness?.route, "/v1/plugin-user/update-user");
  compare(failures, "readiness.scope", readiness?.scope, "membership-replace");
  compare(failures, "readiness.sourceOfTruth", readiness?.sourceOfTruth, expectedSource);
  compare(failures, "readiness.recoveryDrill.enabled", readiness?.recoveryDrill?.enabled, options.expectedRecoveryDrill);
  compare(
    failures,
    "readiness.recoveryDrill.targetConfigured",
    readiness?.recoveryDrill?.targetConfigured,
    options.expectedRecoveryDrill
  );
  compare(failures, "readiness.rollout.mode", readiness?.rollout?.mode, "allowlist");
  compare(failures, "readiness.rollout.allowlistCount", readiness?.rollout?.allowlistCount, options.expectedAllowlistCount);
  compare(failures, "readiness.rollout.percentage", readiness?.rollout?.percentage, 0);
  compare(failures, "readiness.rollout.selectionConfigured", readiness?.rollout?.selectionConfigured, true);
  const gateName = options.expectedMode === "legacy-proxy"
    ? "legacyProxyGate"
    : options.expectedMode === "dual-write"
      ? "dualWriteGate"
      : "identityNativeGate";
  compare(failures, `readiness.${gateName}.executable`, readiness?.[gateName]?.executable, true);

  compare(failures, "decision.mutation", decision?.mutation, false);
  compare(failures, "decision.mode", decision?.mode, options.expectedMode);
  compare(failures, "decision.route", decision?.route, "/v1/plugin-user/update-user");
  compare(failures, "decision.scope", decision?.scope, "membership-replace");
  compare(failures, "decision.selected", decision?.selected, true);
  compare(failures, "decision.executable", decision?.executable, true);
  compare(failures, "decision.decision", decision?.decision, "selected:allowlist");
  compare(failures, "decision.sourceOfTruth", decision?.sourceOfTruth, expectedSource);

  if (options.expectedMode === "identity-native") {
    compare(failures, "candidate.mutation", candidate?.mutation, false);
    compare(failures, "candidate.sourceOfTruth", candidate?.sourceOfTruth, "identity-candidate");
    if (!Number.isSafeInteger(candidate?.organizationCount) || candidate.organizationCount < 0) {
      failures.push("candidate.organizationCount is not a non-negative integer");
    }
    if (!/^[a-f0-9]{64}$/.test(String(candidate?.snapshotFingerprint ?? ""))) {
      failures.push("candidate.snapshotFingerprint is not a full SHA-256 digest");
    }
  }

  if (Array.isArray(summary?.operations)) {
    for (const operation of summary.operations) {
      if (["pending", "failed"].includes(String(operation?.status))) {
        failures.push(`ledger contains ${String(operation.status)} operations in the last ${options.sinceMinutes} minutes`);
      }
      if (["required", "failed"].includes(String(operation?.compensationStatus))) {
        failures.push(`ledger contains compensation=${String(operation.compensationStatus)} in the last ${options.sinceMinutes} minutes`);
      }
    }
  } else {
    failures.push("ledger summary operations are unavailable");
  }

  if (!Array.isArray(recent?.operations)) failures.push("recent ledger operations are unavailable");
  if (options.requireAlignment) {
    compare(failures, "alignment.aligned", alignment?.aligned, true);
    compare(failures, "alignment.P0", alignment?.P0, 0);
    compare(failures, "alignment.P1", alignment?.P1, 0);
    compare(failures, "alignment.P2", alignment?.P2, 0);
    compare(failures, "alignment.mismatch", alignment?.mismatch, 0);
  }

  return {
    passed: failures.length === 0,
    checkedAt: new Date().toISOString(),
    target: {
      fingerprint: decision?.targetFingerprint ?? null
    },
    health: {
      status: health.status,
      revision: healthBody.revision ?? null,
      organizationWrite: posture ?? null
    },
    readiness,
    decision,
    ledger: { summary, recent },
    alignment,
    candidate,
    failures
  };
}

export function parseOrganizationWriteWindowGateArgs(argv: string[], env: NodeJS.ProcessEnv = process.env): OrganizationWriteWindowGateOptions {
  const options: OrganizationWriteWindowGateOptions = {
    adapterUrl: env.IDENTITY_ADAPTER_URL ?? `http://127.0.0.1:${env.PORT ?? "8086"}`,
    token: env.IDENTITY_IAM_INTERNAL_API_TOKEN ?? env.IDENTITY_INTERNAL_API_TOKEN ?? null,
    legacyUserId: 0,
    expectedMode: "legacy-proxy",
    expectedAllowlistCount: 1,
    sinceMinutes: 60,
    requireAlignment: false,
    expectedRecoveryDrill: false
  };

  for (const arg of argv) {
    if (arg.startsWith("--adapter-url=")) options.adapterUrl = arg.slice("--adapter-url=".length).trim();
    else if (arg.startsWith("--legacy-user-id=")) options.legacyUserId = positiveInteger(arg.slice("--legacy-user-id=".length), "legacy-user-id");
    else if (arg.startsWith("--expected-mode=")) options.expectedMode = modeValue(arg.slice("--expected-mode=".length));
    else if (arg.startsWith("--expected-revision=")) options.expectedRevision = revisionValue(arg.slice("--expected-revision=".length));
    else if (arg.startsWith("--expected-allowlist-count=")) options.expectedAllowlistCount = nonNegativeInteger(arg.slice("--expected-allowlist-count=".length), "expected-allowlist-count");
    else if (arg.startsWith("--since-minutes=")) options.sinceMinutes = boundedInteger(arg.slice("--since-minutes=".length), "since-minutes", 1, 1440);
    else if (arg === "--require-alignment") options.requireAlignment = true;
    else if (arg.startsWith("--expected-recovery-drill=")) {
      options.expectedRecoveryDrill = booleanValue(
        arg.slice("--expected-recovery-drill=".length),
        "expected-recovery-drill"
      );
    }
    else if (arg.startsWith("--token=")) throw new Error("Do not pass tokens on the command line; use IDENTITY_IAM_INTERNAL_API_TOKEN.");
    else throw new Error(`Unknown argument: ${arg}`);
  }

  if (!options.adapterUrl) throw new Error("--adapter-url must not be empty");
  if (!options.legacyUserId) throw new Error("--legacy-user-id is required");
  if (options.expectedMode === "legacy-proxy" && options.requireAlignment) {
    throw new Error("--require-alignment is only valid for a dual-write or identity-native gate.");
  }
  if (options.expectedRecoveryDrill && options.expectedMode !== "dual-write") {
    throw new Error("--expected-recovery-drill=true requires --expected-mode=dual-write");
  }
  return options;
}

async function getJson(fetcher: typeof fetch, url: string, headers?: Record<string, string>): Promise<JsonResponse> {
  const response = await fetcher(url, { headers, redirect: "error", signal: AbortSignal.timeout(10_000) });
  const text = await response.text();
  let body: Record<string, any>;
  try {
    body = text ? JSON.parse(text) as Record<string, any> : {};
  } catch {
    throw new Error(`GET ${url} returned non-JSON content with HTTP ${response.status}`);
  }
  if (!response.ok) throw new Error(`GET ${url} failed with HTTP ${response.status}`);
  return { status: response.status, body };
}

function compare(failures: string[], field: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) failures.push(`${field} expected ${String(expected)}, got ${String(actual)}`);
}

function modeValue(value: string): OrganizationWriteWindowMode {
  if (value !== "legacy-proxy" && value !== "dual-write" && value !== "identity-native") {
    throw new Error("expected-mode must be legacy-proxy, dual-write, or identity-native");
  }
  return value;
}

function revisionValue(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(normalized)) throw new Error("expected-revision must be a full 40-character Git SHA");
  return normalized;
}

function positiveInteger(value: string, name: string): number {
  return boundedInteger(value, name, 1, Number.MAX_SAFE_INTEGER);
}

function nonNegativeInteger(value: string, name: string): number {
  return boundedInteger(value, name, 0, Number.MAX_SAFE_INTEGER);
}

function boundedInteger(value: string, name: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return parsed;
}

function booleanValue(value: string, name: string): boolean {
  if (value !== "true" && value !== "false") throw new Error(`${name} must be true or false`);
  return value === "true";
}

async function main(): Promise<void> {
  const result = await runOrganizationWriteWindowGate(parseOrganizationWriteWindowGateArgs(process.argv.slice(2)));
  console.log(JSON.stringify(result, null, 2));
  if (!result.passed) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
