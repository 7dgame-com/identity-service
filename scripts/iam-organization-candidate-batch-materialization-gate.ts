import { createHash, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

export interface OrganizationCandidateBatchGateOptions {
  environment: "xrteeth-develop" | "xrteeth-production";
  adapterUrl: string;
  token: string | null;
  expectedRevision: string;
  expectedLegacySubjectCount: number;
  expectedProtectedSubjectCount: number;
  apply: boolean;
  verifyOutcome: boolean;
  expectRestored: boolean;
  planToken: string | null;
  idempotencyKey: string | null;
}

interface JsonResponse {
  status: number;
  body: Record<string, any>;
}

const INTERNAL_TOKEN_ENV = "IDENTITY_IAM_INTERNAL_API_TOKEN";
const PLAN_TOKEN_ENV = "IDENTITY_IAM_ORG_CANDIDATE_BATCH_PLAN_TOKEN";
const IDEMPOTENCY_KEY_ENV = "IDENTITY_IAM_ORG_CANDIDATE_BATCH_IDEMPOTENCY_KEY";
const FULL_REVISION = /^[a-f0-9]{40}$/;
const FULL_DIGEST = /^[a-f0-9]{64}$/;
const SHORT_DIGEST = /^[a-f0-9]{16}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const CONTRACT_PREFIX = "iam-organization-candidate-batch-materialization";

export async function runOrganizationCandidateBatchGate(
  options: OrganizationCandidateBatchGateOptions,
  fetcher: typeof fetch = fetch
) {
  const base = validateOptions(options);
  if (options.expectRestored) return runRestoredGate(options, base, fetcher);
  if (options.verifyOutcome) return runOutcomeVerificationGate(options, base, fetcher);

  let health: JsonResponse;
  let readiness: JsonResponse;
  let preview: JsonResponse;
  try {
    ({ health, readiness, preview } = await collectPreflight(options, base, fetcher));
  } catch {
    return failedResult(options.apply ? "apply" : "preview", [
      "candidate batch preflight failed; no POST was attempted"
    ]);
  }
  const failures: string[] = [];
  assertHealth(failures, health, options, options.apply);
  assertReadiness(failures, readiness, options, options.apply);
  assertPreview(failures, preview, options, options.apply, false);
  const previewData = preview.body.data;
  const sanitized = sanitizedSnapshot(health, previewData);
  if (failures.length > 0 || !options.apply) {
    return {
      passed: failures.length === 0,
      mode: options.apply ? "apply" : "preview",
      checkedAt: new Date().toISOString(),
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      ...sanitized,
      planToken: !options.apply && failures.length === 0 ? validDigest(previewData?.planToken) : null,
      failures
    };
  }

  let applyResponse: JsonResponse;
  try {
    applyResponse = await requestJson(
      fetcher,
      `${base}/internal/iam/organization-write/candidate-batch-materialization/apply`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-identity-internal-token": options.token as string,
          "x-identity-expected-revision": options.expectedRevision,
          "idempotency-key": options.idempotencyKey as string
        },
        body: JSON.stringify({ planToken: options.planToken })
      },
      201
    );
  } catch {
    return {
      ...failedResult("apply", ["candidate batch POST outcome is unknown; do not retry automatically"]),
      applyAttempted: true,
      outcomeUnknown: true,
      ...sanitized,
      operation: { idempotencyKeyDigest: digest(options.idempotencyKey as string), planTokenDigest: null }
    };
  }

  let freshHealth: JsonResponse;
  let freshReadiness: JsonResponse;
  let freshPreview: JsonResponse;
  try {
    ({ health: freshHealth, readiness: freshReadiness, preview: freshPreview } =
      await collectPreflight(options, base, fetcher));
  } catch {
    return {
      ...failedResult("apply", ["candidate batch POST returned 201 but full postcheck is incomplete; do not resend POST"]),
      applyAttempted: true,
      postcheckIncomplete: true,
      ...sanitized,
      operation: sanitizedApply(applyResponse.body.data, options)
    };
  }

  const finalFailures = [...failures];
  assertHealth(finalFailures, freshHealth, options, true);
  assertReadiness(finalFailures, freshReadiness, options, true);
  assertPreview(finalFailures, freshPreview, options, true, true);
  assertApply(finalFailures, applyResponse, options);
  const freshData = freshPreview.body.data;
  if (finalFailures.length > 0) {
    finalFailures.push("candidate batch postcheck did not prove completion; do not resend POST automatically");
  }
  return {
    passed: finalFailures.length === 0,
    mode: "apply",
    checkedAt: new Date().toISOString(),
    applyAttempted: true,
    outcomeUnknown: false,
    postcheckIncomplete: finalFailures.length > 0,
    ...sanitizedSnapshot(freshHealth, freshData),
    planToken: null,
    operation: sanitizedApply(applyResponse.body.data, options),
    failures: finalFailures
  };
}

export function parseOrganizationCandidateBatchGateArgs(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): OrganizationCandidateBatchGateOptions {
  const options: OrganizationCandidateBatchGateOptions = {
    environment: "xrteeth-develop",
    adapterUrl: "",
    token: env[INTERNAL_TOKEN_ENV]?.trim() || null,
    expectedRevision: "",
    expectedLegacySubjectCount: 0,
    expectedProtectedSubjectCount: 0,
    apply: false,
    verifyOutcome: false,
    expectRestored: false,
    planToken: env[PLAN_TOKEN_ENV]?.trim().toLowerCase() || null,
    idempotencyKey: env[IDEMPOTENCY_KEY_ENV]?.trim() || null
  };
  const seen = new Set<string>();
  const claim = (name: string) => {
    if (seen.has(name)) throw new Error(`Duplicate ${name} argument.`);
    seen.add(name);
  };
  for (const arg of argv) {
    if (arg === "--apply") {
      claim("--apply");
      options.apply = true;
    } else if (arg === "--verify-outcome") {
      claim("--verify-outcome");
      options.verifyOutcome = true;
    } else if (arg === "--expect-restored") {
      claim("--expect-restored");
      options.expectRestored = true;
    } else if (arg.startsWith("--adapter-url=")) {
      claim("--adapter-url");
      options.adapterUrl = arg.slice("--adapter-url=".length);
    } else if (arg.startsWith("--environment=")) {
      claim("--environment");
      const environment = arg.slice("--environment=".length);
      if (environment !== "xrteeth-develop" && environment !== "xrteeth-production") {
        throw new Error("Environment must be xrteeth-develop or xrteeth-production.");
      }
      options.environment = environment;
    } else if (arg.startsWith("--expected-revision=")) {
      claim("--expected-revision");
      options.expectedRevision = arg.slice("--expected-revision=".length);
    } else if (arg.startsWith("--expected-legacy-subject-count=")) {
      claim("--expected-legacy-subject-count");
      options.expectedLegacySubjectCount = integer(
        arg.slice("--expected-legacy-subject-count=".length),
        "expected-legacy-subject-count",
        1,
        5000
      );
    } else if (arg.startsWith("--expected-protected-subject-count=")) {
      claim("--expected-protected-subject-count");
      options.expectedProtectedSubjectCount = integer(
        arg.slice("--expected-protected-subject-count=".length),
        "expected-protected-subject-count",
        1,
        4999
      );
    } else if (
      arg === "--token" || arg.startsWith("--token=") || arg.startsWith("--internal-token=")
    ) {
      throw new Error(`Do not pass tokens on the command line; use ${INTERNAL_TOKEN_ENV}.`);
    } else if (arg.startsWith("--plan-token") || arg.startsWith("--idempotency-key")) {
      throw new Error(`Do not pass write secrets on the command line; use ${PLAN_TOKEN_ENV} and ${IDEMPOTENCY_KEY_ENV}.`);
    } else {
      throw new Error("Unknown or disallowed argument.");
    }
  }
  validateOptions(options);
  return options;
}

async function collectPreflight(
  options: OrganizationCandidateBatchGateOptions,
  base: string,
  fetcher: typeof fetch
) {
  const headers = {
    "x-identity-internal-token": options.token as string,
    "x-identity-expected-revision": options.expectedRevision
  };
  const [health, readiness, preview] = await Promise.all([
    requestJson(fetcher, `${base}/health`),
    requestJson(fetcher, `${base}/internal/iam/organization-write/readiness`, {
      headers: { "x-identity-internal-token": options.token as string }
    }),
    requestJson(fetcher, `${base}/internal/iam/organization-write/candidate-batch-materialization/preview`, {
      headers
    })
  ]);
  return { health, readiness, preview };
}

async function runRestoredGate(
  options: OrganizationCandidateBatchGateOptions,
  base: string,
  fetcher: typeof fetch
) {
  let health: JsonResponse;
  let readiness: JsonResponse;
  try {
    [health, readiness] = await Promise.all([
      requestJson(fetcher, `${base}/health`),
      requestJson(fetcher, `${base}/internal/iam/organization-write/readiness`, {
        headers: { "x-identity-internal-token": options.token as string }
      })
    ]);
  } catch {
    return failedResult("expect-restored", ["candidate batch restored-posture verification failed"]);
  }
  const failures: string[] = [];
  assertHealth(failures, health, options, false, true);
  assertReadiness(failures, readiness, options, false, true);
  return {
    passed: failures.length === 0,
    mode: "expect-restored",
    checkedAt: new Date().toISOString(),
    applyAttempted: false,
    outcomeUnknown: false,
    postcheckIncomplete: false,
    revision: validRevision(health.body.revision),
    failures
  };
}

async function runOutcomeVerificationGate(
  options: OrganizationCandidateBatchGateOptions,
  base: string,
  fetcher: typeof fetch
) {
  let health: JsonResponse;
  let readiness: JsonResponse;
  let preview: JsonResponse;
  try {
    ({ health, readiness, preview } = await collectPreflight(options, base, fetcher));
  } catch {
    return {
      ...failedResult("verify-outcome", ["candidate batch outcome verification failed; do not resend POST"]),
      outcomeUnknown: true
    };
  }
  const failures: string[] = [];
  assertHealth(failures, health, options, false);
  assertReadiness(failures, readiness, options, false);
  assertPreview(failures, preview, options, false, true);
  if (failures.length > 0) failures.push("candidate batch outcome is not proven; do not resend POST automatically");
  return {
    passed: failures.length === 0,
    mode: "verify-outcome",
    checkedAt: new Date().toISOString(),
    applyAttempted: false,
    outcomeUnknown: failures.length > 0,
    postcheckIncomplete: false,
    ...sanitizedSnapshot(health, preview.body.data),
    planToken: null,
    operation: { idempotencyKeyDigest: digest(options.idempotencyKey as string), planTokenDigest: null },
    failures
  };
}

function assertHealth(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateBatchGateOptions,
  applyEnabled: boolean,
  restored = false
): void {
  equal(failures, "health HTTP status", response.status, 200);
  equal(failures, "health status", response.body.status, "ok");
  equal(failures, "health service", response.body.service, "identity-adapter");
  equal(failures, "health revision", response.body.revision, options.expectedRevision);
  const posture = response.body.capabilities?.organizationWrite;
  equal(failures, "health organization mode", posture?.mode, "disabled");
  equal(failures, "health route integration", posture?.routeIntegrationEnabled, false);
  equal(failures, "health dual-write execution", posture?.dualWriteExecutionEnabled, false);
  equal(failures, "health single materialization", posture?.candidateMaterializationEnabled, false);
  equal(failures, "health single materialization target", posture?.candidateMaterializationTargetConfigured, false);
  equal(failures, "health batch enabled", posture?.candidateBatchMaterializationEnabled, applyEnabled);
  equal(
    failures,
    "health batch environment",
    posture?.candidateBatchMaterializationEnvironment,
    restored ? "disabled" : options.environment
  );
  equal(failures, "health rollout mode", posture?.rolloutMode, "off");
  equal(failures, "health rollout allowlist count", posture?.rolloutAllowlistCount, 0);
  equal(failures, "health rollout percentage", posture?.rolloutPercentage, 0);
}

function assertReadiness(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateBatchGateOptions,
  applyEnabled: boolean,
  restored = false
): void {
  assertEnvelope(failures, "readiness", response, "iam-organization-write");
  const batch = response.body.data?.candidateBatchMaterialization;
  equal(failures, "readiness contract", batch?.contract, contract(options.environment));
  equal(failures, "readiness enabled", batch?.enabled, applyEnabled);
  equal(failures, "readiness environment", batch?.environment, restored ? "disabled" : options.environment);
  equal(failures, "readiness plan key", batch?.planHmacKeyConfigured, !restored);
  equal(
    failures,
    "readiness expected Legacy subjects",
    batch?.expectedLegacySubjectCount,
    restored ? 0 : options.expectedLegacySubjectCount
  );
  equal(
    failures,
    "readiness expected protected subjects",
    batch?.expectedProtectedSubjectCount,
    restored ? 0 : options.expectedProtectedSubjectCount
  );
  equal(failures, "readiness preview", batch?.canPreview, !restored);
  equal(failures, "readiness apply", batch?.canApply, applyEnabled && !restored);
  equal(failures, "readiness source", batch?.sourceOfTruth, "legacy");
  equal(failures, "readiness Legacy mutation", batch?.mutatesLegacy, false);
  equal(failures, "readiness protected writes", batch?.protectedSubjectsWritten, false);
  equal(failures, "readiness write scope", batch?.writeScope, "identity-candidate-only");
}

function assertPreview(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateBatchGateOptions,
  applyEnabled: boolean,
  completed: boolean
): void {
  assertEnvelope(failures, "preview", response, "iam-organization-candidate-batch-materialization-preview");
  const data = response.body.data;
  equal(failures, "preview contract", data?.contract, contract(options.environment));
  equal(failures, "preview mutation", data?.mutation, false);
  equal(failures, "preview executable", data?.executable, true);
  equal(failures, "preview apply enabled", data?.applyEnabled, applyEnabled);
  equal(failures, "preview Legacy subjects", data?.legacySubjectCount, options.expectedLegacySubjectCount);
  equal(failures, "preview protected subjects", data?.protectedSubjectCount, options.expectedProtectedSubjectCount);
  equal(
    failures,
    "preview ordinary subjects",
    data?.ordinarySubjectCount,
    options.expectedLegacySubjectCount - options.expectedProtectedSubjectCount
  );
  equal(failures, "preview blocked ordinary subjects", data?.ordinaryBlockedCount, 0);
  equal(failures, "preview inactive ordinary subjects", data?.inactiveOrdinaryCount, 0);
  nonNegative(failures, "preview missing ordinary subjects", data?.ordinaryMissingCount);
  equal(failures, "preview missing ordinary subjects", data?.ordinaryMissingCount, completed ? 0 : data?.ordinaryMissingCount);
  nonNegative(failures, "preview aligned ordinary subjects", data?.ordinaryAlignedCount);
  equal(
    failures,
    "preview ordinary coverage",
    Number(data?.ordinaryAlignedCount) + Number(data?.ordinaryMissingCount),
    data?.ordinarySubjectCount
  );
  nonNegative(failures, "preview aligned protected subjects", data?.protectedAlignedCount);
  nonNegative(failures, "preview missing protected subjects", data?.protectedMissingCount);
  equal(
    failures,
    "preview protected coverage",
    Number(data?.protectedAlignedCount) + Number(data?.protectedMissingCount),
    data?.protectedSubjectCount
  );
  equal(failures, "preview source", data?.sourceOfTruth, "legacy");
  equal(failures, "preview Legacy mutation", data?.legacyWritePerformed, false);
  equal(failures, "preview Identity mutation", data?.identityCandidateWritePerformed, false);
  equal(failures, "preview protected writes", data?.protectedSubjectWritePerformed, false);
  equal(failures, "preview blocker count", Array.isArray(data?.blockedReasons) ? data.blockedReasons.length : -1, 0);
  pattern(failures, "preview plan token", data?.planToken, FULL_DIGEST);
  if ((options.apply || options.verifyOutcome) && !constantTimeDigestEqual(data?.planToken, options.planToken)) {
    failures.push("preview plan token does not match the reviewed token");
  }
}

function assertApply(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateBatchGateOptions
): void {
  assertEnvelope(failures, "apply", response, "iam-organization-candidate-batch-materialization", 201);
  const data = response.body.data;
  equal(failures, "apply contract", data?.contract, contract(options.environment));
  equal(failures, "apply completed", data?.completed, true);
  equal(failures, "apply Legacy subjects", data?.legacySubjectCount, options.expectedLegacySubjectCount);
  equal(
    failures,
    "apply ordinary subjects",
    data?.ordinarySubjectCount,
    options.expectedLegacySubjectCount - options.expectedProtectedSubjectCount
  );
  equal(failures, "apply protected skips", data?.protectedSkippedCount, options.expectedProtectedSubjectCount);
  nonNegative(failures, "apply applied count", data?.appliedCount);
  nonNegative(failures, "apply replay count", data?.replayedCount);
  nonNegative(failures, "apply aligned skip count", data?.skippedAlignedCount);
  equal(
    failures,
    "apply ordinary coverage",
    Number(data?.appliedCount) + Number(data?.replayedCount) + Number(data?.skippedAlignedCount),
    data?.ordinarySubjectCount
  );
  equal(failures, "apply mutation flag", data?.mutation, Number(data?.appliedCount) > 0);
  equal(failures, "apply source", data?.sourceOfTruth, "legacy");
  equal(failures, "apply Legacy mutation", data?.legacyWritePerformed, false);
  equal(failures, "apply protected writes", data?.protectedSubjectWritePerformed, false);
  equal(failures, "apply write scope", data?.writeScope, "identity-candidate-only");
  pattern(failures, "apply plan token digest", data?.planTokenDigest, SHORT_DIGEST);
  equal(
    failures,
    "apply reviewed plan token digest",
    data?.planTokenDigest,
    digest(options.planToken as string).slice(0, 16)
  );
}

function validateOptions(options: OrganizationCandidateBatchGateOptions): string {
  if (options.environment !== "xrteeth-develop" && options.environment !== "xrteeth-production") {
    throw new Error("Environment must be xrteeth-develop or xrteeth-production.");
  }
  if ([options.apply, options.verifyOutcome, options.expectRestored].filter(Boolean).length > 1) {
    throw new Error("Apply, outcome-verification and restored-posture modes are mutually exclusive.");
  }
  if (!options.token || options.token.length > 1024) throw new Error(`${INTERNAL_TOKEN_ENV} is required.`);
  if (!FULL_REVISION.test(options.expectedRevision)) throw new Error("A full expected revision is required.");
  const base = loopbackBase(options.adapterUrl);
  if (!options.expectRestored) {
    if (!Number.isInteger(options.expectedLegacySubjectCount) || options.expectedLegacySubjectCount < 2 ||
      options.expectedLegacySubjectCount > 5000) {
      throw new Error("Expected Legacy subject count must be between 2 and 5000.");
    }
    if (!Number.isInteger(options.expectedProtectedSubjectCount) || options.expectedProtectedSubjectCount < 1 ||
      options.expectedProtectedSubjectCount >= options.expectedLegacySubjectCount) {
      throw new Error("Expected protected subject count is invalid.");
    }
    if (options.environment === "xrteeth-production" &&
      (options.expectedLegacySubjectCount !== 807 || options.expectedProtectedSubjectCount !== 2)) {
      throw new Error("xrteeth-production requires the reviewed 807/2 subject universe.");
    }
  }
  if (options.apply || options.verifyOutcome) {
    if (!options.planToken || !FULL_DIGEST.test(options.planToken)) throw new Error(`${PLAN_TOKEN_ENV} is required.`);
    if (!options.idempotencyKey || options.idempotencyKey.length < 1 || options.idempotencyKey.length > 180) {
      throw new Error(`${IDEMPOTENCY_KEY_ENV} is required.`);
    }
  }
  return base;
}

function contract(environment: OrganizationCandidateBatchGateOptions["environment"]): string {
  return `${CONTRACT_PREFIX}/${environment}/v1`;
}

function loopbackBase(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Adapter URL is invalid.");
  }
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname) || url.username || url.password ||
    (url.pathname !== "" && url.pathname !== "/") || url.search || url.hash) {
    throw new Error("Adapter URL must be a credential-free loopback HTTP origin.");
  }
  return url.origin;
}

async function requestJson(
  fetcher: typeof fetch,
  url: string,
  init: RequestInit = {},
  expectedStatus = 200
): Promise<JsonResponse> {
  const response = await fetcher(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(10_000) });
  if (response.status !== expectedStatus || response.status >= 300 && response.status < 400) {
    throw new Error("Unexpected HTTP status.");
  }
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) throw new Error("Expected JSON response.");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > 1_048_576) throw new Error("Response exceeds reviewed bound.");
  const body = JSON.parse(text);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Response body is invalid.");
  return { status: response.status, body };
}

function assertEnvelope(
  failures: string[],
  label: string,
  response: JsonResponse,
  capability: string,
  status = 200
): void {
  equal(failures, `${label} HTTP status`, response.status, status);
  equal(failures, `${label} status`, response.body.status, "ok");
  equal(failures, `${label} service`, response.body.service, "identity-adapter");
  equal(failures, `${label} capability`, response.body.capability, capability);
}

function sanitizedSnapshot(health: JsonResponse, data: Record<string, any>) {
  return {
    revision: validRevision(health.body.revision),
    counts: {
      legacySubjects: safeInteger(data?.legacySubjectCount),
      ordinarySubjects: safeInteger(data?.ordinarySubjectCount),
      protectedSubjects: safeInteger(data?.protectedSubjectCount),
      ordinaryAligned: safeInteger(data?.ordinaryAlignedCount),
      ordinaryMissing: safeInteger(data?.ordinaryMissingCount),
      ordinaryBlocked: safeInteger(data?.ordinaryBlockedCount),
      inactiveOrdinary: safeInteger(data?.inactiveOrdinaryCount),
      protectedMissing: safeInteger(data?.protectedMissingCount)
    },
    safety: {
      sourceOfTruth: data?.sourceOfTruth === "legacy" ? "legacy" : null,
      legacyWritePerformed: data?.legacyWritePerformed === false ? false : null,
      protectedSubjectWritePerformed: data?.protectedSubjectWritePerformed === false ? false : null
    }
  };
}

function sanitizedApply(data: Record<string, any>, options: OrganizationCandidateBatchGateOptions) {
  return {
    completed: data?.completed === true,
    mutation: typeof data?.mutation === "boolean" ? data.mutation : null,
    appliedCount: safeInteger(data?.appliedCount),
    replayedCount: safeInteger(data?.replayedCount),
    skippedAlignedCount: safeInteger(data?.skippedAlignedCount),
    protectedSkippedCount: safeInteger(data?.protectedSkippedCount),
    planTokenDigest: SHORT_DIGEST.test(String(data?.planTokenDigest ?? "")) ? data.planTokenDigest : null,
    idempotencyKeyDigest: digest(options.idempotencyKey as string)
  };
}

function failedResult(mode: string, failures: string[]) {
  return {
    passed: false,
    mode,
    checkedAt: new Date().toISOString(),
    applyAttempted: false,
    outcomeUnknown: false,
    postcheckIncomplete: false,
    failures
  };
}

function equal(failures: string[], label: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) failures.push(`${label} expected ${String(expected)}, got ${safeDisplay(actual)}`);
}

function pattern(failures: string[], label: string, actual: unknown, expected: RegExp): void {
  if (typeof actual !== "string" || !expected.test(actual)) failures.push(`${label} is invalid`);
}

function nonNegative(failures: string[], label: string, actual: unknown): void {
  if (!Number.isSafeInteger(actual) || Number(actual) < 0) failures.push(`${label} is invalid`);
}

function safeDisplay(value: unknown): string {
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") {
    return String(value);
  }
  return "<redacted>";
}

function integer(value: string, label: string, min: number, max: number): number {
  if (!/^\d+$/.test(value)) throw new Error(`${label} must be an integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${label} is outside the reviewed bound.`);
  return parsed;
}

function safeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
}

function validRevision(value: unknown): string | null {
  return typeof value === "string" && FULL_REVISION.test(value) ? value : null;
}

function validDigest(value: unknown): string | null {
  return typeof value === "string" && FULL_DIGEST.test(value) ? value : null;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function constantTimeDigestEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string" ||
    !FULL_DIGEST.test(left) || !FULL_DIGEST.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

async function main(): Promise<void> {
  try {
    const result = await runOrganizationCandidateBatchGate(
      parseOrganizationCandidateBatchGateArgs(process.argv.slice(2))
    );
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = result.passed ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Candidate batch gate failed."}\n`);
    process.exitCode = 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) await main();
