import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

export interface OrganizationCandidateMaterializationGateOptions {
  adapterUrl: string;
  token: string | null;
  legacyUserId: number;
  apply: boolean;
  expectedRevision?: string;
  expectedSnapshotFingerprint?: string;
  idempotencyKey: string | null;
  sinceMinutes: number;
  expectRestored?: boolean;
  verifyOutcome?: boolean;
}

interface JsonResponse {
  status: number;
  body: Record<string, any>;
}

interface ReadOnlyPreflight {
  base: string;
  headers: Record<string, string>;
  health: JsonResponse;
  readiness: JsonResponse;
  preview?: JsonResponse;
  alignment?: JsonResponse;
  summary?: JsonResponse;
  recent?: JsonResponse;
  failures: string[];
}

const INTERNAL_TOKEN_ENV = "IDENTITY_IAM_INTERNAL_API_TOKEN";
const IDEMPOTENCY_KEY_ENV = "IDENTITY_IAM_ORG_CANDIDATE_MATERIALIZATION_IDEMPOTENCY_KEY";
const FULL_REVISION = /^[a-f0-9]{40}$/;
const FULL_FINGERPRINT = /^[a-f0-9]{64}$/;
const SHORT_FINGERPRINT = /^[a-f0-9]{16}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const COMPLETED_IDENTITY_STATUSES = [
  "candidate-materialized",
  "candidate-recovered-from-current-legacy"
] as const;
const CANDIDATE_IDENTITY_STATUSES = [
  "pending",
  ...COMPLETED_IDENTITY_STATUSES,
  "candidate-materialization-failed",
  "candidate-write-outcome-unknown",
  "candidate-postcheck-failed",
  "candidate-recovery-failed"
] as const;

export async function runOrganizationCandidateMaterializationGate(
  options: OrganizationCandidateMaterializationGateOptions,
  fetcher: typeof fetch = fetch
) {
  const validated = validateOptions(options);
  if (options.expectRestored) {
    return runRestoredPostureGate(options, validated.base, fetcher);
  }
  if (options.verifyOutcome) {
    return runOutcomeVerificationGate(options, validated.base, fetcher);
  }
  let preflight: ReadOnlyPreflight;
  try {
    preflight = await collectReadOnlyPreflight(options, validated.base, fetcher);
  } catch {
    return {
      passed: false,
      mode: options.apply ? "apply" : "preview",
      checkedAt: new Date().toISOString(),
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      failures: ["candidate materialization preflight failed; no POST was attempted"]
    };
  }
  const preflightOutput = sanitizedPreflight(preflight, options.sinceMinutes);

  if (preflight.failures.length > 0 || !options.apply) {
    return {
      passed: preflight.failures.length === 0,
      mode: options.apply ? "apply" : "preview",
      checkedAt: new Date().toISOString(),
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      ...preflightOutput,
      failures: preflight.failures
    };
  }

  const expectedSnapshotFingerprint = options.expectedSnapshotFingerprint as string;
  const idempotencyKey = options.idempotencyKey as string;
  let applyResponse: JsonResponse;
  try {
    applyResponse = await requestJson(
      fetcher,
      "candidate materialization apply",
      `${validated.base}/internal/iam/organization-write/subjects/${options.legacyUserId}/materialize-candidate`,
      {
        method: "POST",
        headers: {
          ...preflight.headers,
          "content-type": "application/json",
          "Idempotency-Key": idempotencyKey,
          "X-Identity-Expected-Revision": options.expectedRevision as string
        },
        body: JSON.stringify({ expectedSnapshotFingerprint })
      },
      201
    );
  } catch {
    return {
      passed: false,
      mode: "apply",
      checkedAt: new Date().toISOString(),
      applyAttempted: true,
      outcomeUnknown: true,
      postcheckIncomplete: false,
      ...preflightOutput,
      operation: {
        operationKeyDigest: null,
        idempotencyKeyDigest: digest(idempotencyKey)
      },
      failures: ["candidate materialization POST outcome is unknown; do not retry automatically"]
    };
  }

  let freshHealth: JsonResponse;
  let freshAlignment: JsonResponse;
  let freshSummary: JsonResponse;
  let freshRecent: JsonResponse;
  try {
    [freshHealth, freshAlignment, freshSummary, freshRecent] = await Promise.all([
      requestJson(fetcher, "fresh health", `${validated.base}/health`),
      requestJson(
        fetcher,
        "fresh subject alignment",
        `${validated.base}/internal/iam/organization-write/subjects/${options.legacyUserId}/alignment`,
        { headers: preflight.headers }
      ),
      requestJson(
        fetcher,
        "fresh ledger summary",
        `${validated.base}/internal/iam/organization-write/operations/summary?sinceMinutes=${options.sinceMinutes}`,
        { headers: preflight.headers }
      ),
      requestJson(
        fetcher,
        "fresh ledger recent",
        `${validated.base}/internal/iam/organization-write/operations/recent?sinceMinutes=${options.sinceMinutes}&limit=200`,
        { headers: preflight.headers }
      )
    ]);
  } catch {
    const applyData = applyResponse.body.data;
    return {
      passed: false,
      mode: "apply",
      checkedAt: new Date().toISOString(),
      applyAttempted: true,
      outcomeUnknown: false,
      postcheckIncomplete: true,
      ...preflightOutput,
      operation: {
        httpStatus: applyResponse.status,
        operationKeyDigest: isShortFingerprint(applyData?.operationKeyDigest)
          ? String(applyData.operationKeyDigest)
          : null,
        idempotencyKeyDigest: digest(idempotencyKey)
      },
      failures: ["candidate materialization POST returned 201 but postcheck is incomplete; do not resend POST"]
    };
  }

  const failures = [...preflight.failures];
  assertInternalEnvelope(failures, "apply", applyResponse, "iam-organization-candidate-materialization", 201);
  assertHealth(failures, freshHealth, options, "fresh health");
  assertInternalEnvelope(failures, "fresh alignment", freshAlignment, "iam-organization-write-subject-alignment");
  assertInternalEnvelope(failures, "fresh ledger summary", freshSummary, "iam-organization-write-operation-ledger");
  assertInternalEnvelope(failures, "fresh ledger recent", freshRecent, "iam-organization-write-operation-ledger");

  const preview = preflight.preview?.body.data;
  const expectedOrganizationCount = preview?.organizationCount;
  const applyData = applyResponse.body.data;
  const postAlignment = freshAlignment.body.data;
  const afterLedger = inspectLedger(
    failures,
    "fresh ledger",
    freshSummary.body.data,
    freshRecent.body.data,
    options.sinceMinutes
  );
  requireEqual(failures, "fresh ledger unresolved operation count", afterLedger.unresolvedOperationCount, 0);
  assertApplyResponse(failures, applyData, preview, expectedSnapshotFingerprint, expectedOrganizationCount);
  assertExactSubjectAlignment(
    failures,
    "fresh alignment",
    postAlignment,
    options.legacyUserId,
    expectedSnapshotFingerprint,
    expectedOrganizationCount,
    true
  );

  const idempotencyKeyDigest = digest(idempotencyKey);
  const operationKeyDigest = isShortFingerprint(applyData?.operationKeyDigest)
    ? String(applyData.operationKeyDigest)
    : null;
  const matchingOperations = Array.isArray(freshRecent.body.data?.operations)
    ? freshRecent.body.data.operations.filter((operation: Record<string, any>) =>
      operation?.legacyUserId === options.legacyUserId &&
      operation?.idempotencyKeyDigest === idempotencyKeyDigest
    )
    : [];
  requireEqual(failures, "fresh ledger matching operation count", matchingOperations.length, 1);
  const operation = matchingOperations[0];
  requirePattern(failures, "fresh ledger full operation digest", operation?.operationKeyDigest, FULL_FINGERPRINT);
  requirePattern(
    failures,
    "fresh ledger full request fingerprint digest",
    operation?.requestFingerprintDigest,
    FULL_FINGERPRINT
  );
  requireEqual(
    failures,
    "fresh ledger reviewed request fingerprint digest",
    operation?.requestFingerprintDigest,
    digest(expectedSnapshotFingerprint)
  );
  requireEqual(
    failures,
    "fresh ledger operation digest prefix",
    typeof operation?.operationKeyDigest === "string" ? operation.operationKeyDigest.slice(0, 16) : null,
    operationKeyDigest
  );
  requireEqual(failures, "fresh ledger operation mode", operation?.mode, "candidate-materialization");
  requireEqual(failures, "fresh ledger operation status", operation?.status, "completed");
  requireEqual(failures, "fresh ledger Legacy status", operation?.legacyStatus, "read-only");
  requireOneOf(failures, "fresh ledger Identity status", operation?.identityStatus, [...COMPLETED_IDENTITY_STATUSES]);
  requireOneOf(failures, "fresh ledger compensation status", operation?.compensationStatus, ["none", "completed"]);
  requireEqual(
    failures,
    "fresh ledger Identity/compensation pair",
    (operation?.identityStatus === "candidate-materialized" && operation?.compensationStatus === "none") ||
      (operation?.identityStatus === "candidate-recovered-from-current-legacy" &&
        operation?.compensationStatus === "completed"),
    true
  );
  requireEqual(failures, "fresh ledger error code", operation?.errorCode, null);
  requireEqual(failures, "fresh ledger legacy write safety", operation?.metadata?.legacyWritePerformed, false);
  requireEqual(failures, "fresh ledger target digest", operation?.metadata?.targetFingerprint, preview?.targetFingerprint);
  requireEqual(
    failures,
    "fresh ledger snapshot digest",
    operation?.metadata?.snapshotFingerprint,
    shortDigest(expectedSnapshotFingerprint)
  );
  requireEqual(
    failures,
    "fresh ledger organization count",
    operation?.metadata?.organizationCount,
    expectedOrganizationCount
  );

  return {
    passed: failures.length === 0,
    mode: "apply",
    checkedAt: new Date().toISOString(),
    applyAttempted: true,
    outcomeUnknown: false,
    postcheckIncomplete: false,
    ...preflightOutput,
    freshRevision: FULL_REVISION.test(String(freshHealth.body.revision ?? ""))
      ? freshHealth.body.revision
      : null,
    operation: {
      httpStatus: applyResponse.status,
      materialized: applyData?.materialized === true,
      idempotentReplay: applyData?.idempotentReplay === true,
      operationKeyDigest,
      idempotencyKeyDigest,
      organizationCount: safeNonNegativeInteger(applyData?.organizationCount),
      before: sanitizedAlignment(applyData?.before),
      after: sanitizedAlignment(applyData?.after),
      safety: sanitizedSafety(applyData?.safety)
    },
    freshAlignment: sanitizedAlignment(postAlignment),
    ledgerAfter: {
      ...afterLedger,
      matchedOperation: operation ? {
        operationKeyDigest: isFullFingerprint(operation.operationKeyDigest)
          ? String(operation.operationKeyDigest)
          : null,
        requestFingerprintDigest: isFullFingerprint(operation.requestFingerprintDigest)
          ? String(operation.requestFingerprintDigest)
          : null,
        idempotencyKeyDigest,
        mode: operation.mode === "candidate-materialization" ? operation.mode : null,
        status: operation.status === "completed" ? operation.status : null,
        legacyStatus: operation.legacyStatus === "read-only" ? operation.legacyStatus : null,
        identityStatus: COMPLETED_IDENTITY_STATUSES.includes(operation.identityStatus)
          ? operation.identityStatus
          : null,
        compensationStatus: ["none", "completed"].includes(String(operation.compensationStatus))
          ? operation.compensationStatus
          : null,
        errorCode: operation.errorCode === null ? null : "unexpected-non-null"
      } : null
    },
    failures
  };
}

export function parseOrganizationCandidateMaterializationGateArgs(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): OrganizationCandidateMaterializationGateOptions {
  const options: OrganizationCandidateMaterializationGateOptions = {
    adapterUrl: env.IDENTITY_ADAPTER_URL ?? `http://127.0.0.1:${env.PORT ?? "8086"}`,
    token: env.IDENTITY_IAM_INTERNAL_API_TOKEN ?? env.IDENTITY_INTERNAL_API_TOKEN ?? null,
    legacyUserId: 0,
    apply: false,
    idempotencyKey: env[IDEMPOTENCY_KEY_ENV] ?? null,
    sinceMinutes: 60,
    expectRestored: false,
    verifyOutcome: false
  };
  const seenArguments = new Set<string>();
  const claimArgument = (name: string): void => {
    if (seenArguments.has(name)) throw new Error(`Duplicate ${name} argument is not allowed.`);
    seenArguments.add(name);
  };

  for (const arg of argv) {
    if (arg === "--apply") {
      claimArgument("--apply");
      options.apply = true;
    } else if (arg === "--expect-restored") {
      claimArgument("--expect-restored");
      options.expectRestored = true;
    } else if (arg === "--verify-outcome") {
      claimArgument("--verify-outcome");
      options.verifyOutcome = true;
    } else if (arg.startsWith("--adapter-url=")) {
      claimArgument("--adapter-url");
      options.adapterUrl = arg.slice("--adapter-url=".length).trim();
    } else if (arg.startsWith("--legacy-user-id=")) {
      claimArgument("--legacy-user-id");
      options.legacyUserId = positiveInteger(arg.slice("--legacy-user-id=".length), "legacy-user-id");
    } else if (arg.startsWith("--expected-revision=")) {
      claimArgument("--expected-revision");
      options.expectedRevision = revisionValue(arg.slice("--expected-revision=".length));
    } else if (arg.startsWith("--expected-snapshot-fingerprint=")) {
      claimArgument("--expected-snapshot-fingerprint");
      options.expectedSnapshotFingerprint = fingerprintValue(arg.slice("--expected-snapshot-fingerprint=".length));
    } else if (arg.startsWith("--since-minutes=")) {
      claimArgument("--since-minutes");
      options.sinceMinutes = boundedInteger(arg.slice("--since-minutes=".length), "since-minutes", 1, 1440);
    } else if (arg === "--token" || arg.startsWith("--token=") || arg.startsWith("--internal-token=")) {
      throw new Error(`Do not pass tokens on the command line; use ${INTERNAL_TOKEN_ENV}.`);
    } else if (
      arg === "--idempotency-key" ||
      arg.startsWith("--idempotency-key=") ||
      arg === "--key" ||
      arg.startsWith("--key=")
    ) {
      throw new Error(`Do not pass idempotency keys on the command line; use ${IDEMPOTENCY_KEY_ENV}.`);
    } else {
      throw new Error("Unknown or disallowed argument.");
    }
  }

  validateOptions(options);
  return options;
}

async function collectReadOnlyPreflight(
  options: OrganizationCandidateMaterializationGateOptions,
  base: string,
  fetcher: typeof fetch
): Promise<ReadOnlyPreflight> {
  const headers = { "x-identity-internal-token": options.token as string };
  const [health, readiness] = await Promise.all([
    requestJson(fetcher, "health", `${base}/health`),
    requestJson(fetcher, "organization write readiness", `${base}/internal/iam/organization-write/readiness`, { headers })
  ]);
  const failures: string[] = [];
  assertHealth(failures, health, options);
  assertInternalEnvelope(failures, "readiness", readiness, "iam-organization-write");
  assertReadiness(failures, readiness.body.data, options.apply);
  const preflight: ReadOnlyPreflight = { base, headers, health, readiness, failures };
  if (failures.length > 0) return preflight;

  const [preview, alignment, summary, recent] = await Promise.all([
    requestJson(
      fetcher,
      "candidate materialization preview",
      `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/materialization-preview`,
      { headers }
    ),
    requestJson(
      fetcher,
      "subject alignment",
      `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/alignment`,
      { headers }
    ),
    requestJson(
      fetcher,
      "ledger summary",
      `${base}/internal/iam/organization-write/operations/summary?sinceMinutes=${options.sinceMinutes}`,
      { headers }
    ),
    requestJson(
      fetcher,
      "ledger recent",
      `${base}/internal/iam/organization-write/operations/recent?sinceMinutes=${options.sinceMinutes}&limit=200`,
      { headers }
    )
  ]);
  Object.assign(preflight, { preview, alignment, summary, recent });
  assertInternalEnvelope(failures, "preview", preview, "iam-organization-candidate-materialization-preview");
  assertInternalEnvelope(failures, "alignment", alignment, "iam-organization-write-subject-alignment");
  assertInternalEnvelope(failures, "ledger summary", summary, "iam-organization-write-operation-ledger");
  assertInternalEnvelope(failures, "ledger recent", recent, "iam-organization-write-operation-ledger");
  assertPreview(failures, preview.body.data, alignment.body.data, options);
  const ledger = inspectLedger(
    failures,
    "preflight ledger",
    summary.body.data,
    recent.body.data,
    options.sinceMinutes
  );
  requireEqual(failures, "preflight ledger unresolved operation count", ledger.unresolvedOperationCount, 0);
  return preflight;
}

async function runRestoredPostureGate(
  options: OrganizationCandidateMaterializationGateOptions,
  base: string,
  fetcher: typeof fetch
) {
  const headers = { "x-identity-internal-token": options.token as string };
  let health: JsonResponse;
  let readiness: JsonResponse;
  let summary: JsonResponse;
  let recent: JsonResponse;
  try {
    [health, readiness, summary, recent] = await Promise.all([
      requestJson(fetcher, "restored health", `${base}/health`),
      requestJson(fetcher, "restored readiness", `${base}/internal/iam/organization-write/readiness`, { headers }),
      requestJson(
        fetcher,
        "restored ledger summary",
        `${base}/internal/iam/organization-write/operations/summary?sinceMinutes=${options.sinceMinutes}`,
        { headers }
      ),
      requestJson(
        fetcher,
        "restored ledger recent",
        `${base}/internal/iam/organization-write/operations/recent?sinceMinutes=${options.sinceMinutes}&limit=200`,
        { headers }
      )
    ]);
  } catch {
    return {
      passed: false,
      mode: "expect-restored",
      checkedAt: new Date().toISOString(),
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      failures: ["restored posture read-only verification failed; no POST was attempted"]
    };
  }

  const failures: string[] = [];
  assertRestoredHealth(failures, health, options);
  assertInternalEnvelope(failures, "restored readiness", readiness, "iam-organization-write");
  assertInternalEnvelope(failures, "restored ledger summary", summary, "iam-organization-write-operation-ledger");
  assertInternalEnvelope(failures, "restored ledger recent", recent, "iam-organization-write-operation-ledger");
  assertRestoredReadiness(failures, readiness.body.data);
  const ledger = inspectLedger(
    failures,
    "restored ledger",
    summary.body.data,
    recent.body.data,
    options.sinceMinutes
  );
  requireEqual(failures, "restored ledger unresolved operation count", ledger.unresolvedOperationCount, 0);

  const posture = health.body.capabilities?.organizationWrite;
  const materialization = readiness.body.data?.candidateMaterialization;
  const blockers = Array.isArray(materialization?.blockers) ? materialization.blockers : [];
  return {
    passed: failures.length === 0,
    mode: "expect-restored",
    checkedAt: new Date().toISOString(),
    applyAttempted: false,
    outcomeUnknown: false,
    postcheckIncomplete: false,
    revision: FULL_REVISION.test(String(health.body.revision ?? "")) ? health.body.revision : null,
    posture: {
      mode: posture?.mode === "disabled" ? "disabled" : null,
      routeIntegrationEnabled: posture?.routeIntegrationEnabled === true,
      dualWriteExecutionEnabled: posture?.dualWriteExecutionEnabled === true,
      candidateMaterializationEnabled: posture?.candidateMaterializationEnabled === true,
      candidateMaterializationTargetConfigured: posture?.candidateMaterializationTargetConfigured === true,
      rolloutMode: posture?.rolloutMode === "off" ? "off" : null,
      rolloutAllowlistCount: safeNonNegativeInteger(posture?.rolloutAllowlistCount),
      rolloutPercentage: safeNonNegativeInteger(posture?.rolloutPercentage),
      sourceOfTruth: posture?.sourceOfTruth === "legacy" ? "legacy" : null,
      identityNativeSupported: posture?.identityNativeSupported === true
    },
    readiness: {
      repositoryConfigured: readiness.body.data?.repositoryConfigured === true,
      materialization: {
        enabled: materialization?.enabled === true,
        targetConfigured: materialization?.targetConfigured === true,
        schemaReady: materialization?.schemaReady === true,
        canPreview: materialization?.canPreview === true,
        canApply: materialization?.canApply === true,
        blockerCount: blockers.length,
        targetNotConfigured: blockers.includes("target-not-configured"),
        candidateDisabled: blockers.includes("candidate-materialization-disabled")
      }
    },
    ledger,
    failures
  };
}

async function runOutcomeVerificationGate(
  options: OrganizationCandidateMaterializationGateOptions,
  base: string,
  fetcher: typeof fetch
) {
  const headers = { "x-identity-internal-token": options.token as string };
  const idempotencyKeyDigest = digest(options.idempotencyKey as string);
  let health: JsonResponse;
  let readiness: JsonResponse;
  let alignment: JsonResponse;
  let summary: JsonResponse;
  let recent: JsonResponse;
  try {
    [health, readiness, alignment, summary, recent] = await Promise.all([
      requestJson(fetcher, "outcome verification health", `${base}/health`),
      requestJson(fetcher, "outcome verification readiness", `${base}/internal/iam/organization-write/readiness`, { headers }),
      requestJson(
        fetcher,
        "outcome verification alignment",
        `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/alignment`,
        { headers }
      ),
      requestJson(
        fetcher,
        "outcome verification ledger summary",
        `${base}/internal/iam/organization-write/operations/summary?sinceMinutes=${options.sinceMinutes}`,
        { headers }
      ),
      requestJson(
        fetcher,
        "outcome verification ledger recent",
        `${base}/internal/iam/organization-write/operations/recent?sinceMinutes=${options.sinceMinutes}&limit=200`,
        { headers }
      )
    ]);
  } catch {
    return {
      passed: false,
      mode: "verify-outcome",
      checkedAt: new Date().toISOString(),
      applyAttempted: false,
      outcomeUnknown: true,
      postcheckIncomplete: true,
      operation: { idempotencyKeyDigest },
      failures: ["outcome verification is incomplete; do not resend POST automatically"]
    };
  }

  const failures: string[] = [];
  assertRestoredHealth(failures, health, options);
  assertInternalEnvelope(failures, "outcome verification readiness", readiness, "iam-organization-write");
  assertInternalEnvelope(
    failures,
    "outcome verification alignment",
    alignment,
    "iam-organization-write-subject-alignment"
  );
  assertInternalEnvelope(
    failures,
    "outcome verification ledger summary",
    summary,
    "iam-organization-write-operation-ledger"
  );
  assertInternalEnvelope(
    failures,
    "outcome verification ledger recent",
    recent,
    "iam-organization-write-operation-ledger"
  );
  assertRestoredReadiness(failures, readiness.body.data);
  const alignmentData = alignment.body.data;
  requireNonNegativeInteger(failures, "outcome verification organization count", alignmentData?.organizationCount);
  assertExactSubjectAlignment(
    failures,
    "outcome verification alignment",
    alignmentData,
    options.legacyUserId,
    options.expectedSnapshotFingerprint,
    alignmentData?.organizationCount,
    true
  );
  const ledger = inspectLedger(
    failures,
    "outcome verification ledger",
    summary.body.data,
    recent.body.data,
    options.sinceMinutes
  );
  requireEqual(failures, "outcome verification ledger unresolved operation count", ledger.unresolvedOperationCount, 0);

  const operations = Array.isArray(recent.body.data?.operations) ? recent.body.data.operations : [];
  const matchingOperations = operations.filter((operation: Record<string, any>) =>
    operation?.legacyUserId === options.legacyUserId &&
    operation?.idempotencyKeyDigest === idempotencyKeyDigest
  );
  requireEqual(failures, "outcome verification matching operation count", matchingOperations.length, 1);
  const operation = matchingOperations[0];
  requirePattern(failures, "outcome verification full operation digest", operation?.operationKeyDigest, FULL_FINGERPRINT);
  requirePattern(
    failures,
    "outcome verification full request fingerprint digest",
    operation?.requestFingerprintDigest,
    FULL_FINGERPRINT
  );
  requireEqual(
    failures,
    "outcome verification reviewed request fingerprint digest",
    operation?.requestFingerprintDigest,
    digest(options.expectedSnapshotFingerprint as string)
  );
  requireEqual(failures, "outcome verification operation mode", operation?.mode, "candidate-materialization");
  requireEqual(failures, "outcome verification operation status", operation?.status, "completed");
  requireEqual(failures, "outcome verification Legacy status", operation?.legacyStatus, "read-only");
  requireOneOf(
    failures,
    "outcome verification Identity status",
    operation?.identityStatus,
    [...COMPLETED_IDENTITY_STATUSES]
  );
  requireOneOf(
    failures,
    "outcome verification compensation status",
    operation?.compensationStatus,
    ["none", "completed"]
  );
  requireEqual(
    failures,
    "outcome verification Identity/compensation pair",
    (operation?.identityStatus === "candidate-materialized" && operation?.compensationStatus === "none") ||
      (operation?.identityStatus === "candidate-recovered-from-current-legacy" &&
        operation?.compensationStatus === "completed"),
    true
  );
  requireEqual(failures, "outcome verification error code", operation?.errorCode, null);
  requireEqual(failures, "outcome verification legacy write safety", operation?.metadata?.legacyWritePerformed, false);
  requireEqual(
    failures,
    "outcome verification snapshot digest",
    operation?.metadata?.snapshotFingerprint,
    shortDigest(options.expectedSnapshotFingerprint as string)
  );
  requireEqual(
    failures,
    "outcome verification target digest",
    operation?.metadata?.targetFingerprint,
    shortDigest(`legacy:${options.legacyUserId}`)
  );
  requireEqual(
    failures,
    "outcome verification organization count",
    operation?.metadata?.organizationCount,
    alignmentData?.organizationCount
  );
  if (
    matchingOperations.some((candidate: Record<string, any>) =>
      candidate?.status === "failed" && candidate?.compensationStatus === "required"
    )
  ) {
    failures.push("outcome verification found recovery-required state; stop and obtain separate recovery approval");
  }
  if (failures.length > 0) {
    failures.push("outcome verification did not prove completion; do not resend POST automatically");
  }

  return {
    passed: failures.length === 0,
    mode: "verify-outcome",
    checkedAt: new Date().toISOString(),
    applyAttempted: false,
    outcomeUnknown: failures.length > 0,
    postcheckIncomplete: false,
    revision: FULL_REVISION.test(String(health.body.revision ?? "")) ? health.body.revision : null,
    target: {
      fingerprint: shortDigest(`legacy:${options.legacyUserId}`),
      snapshotFingerprint: options.expectedSnapshotFingerprint,
      organizationCount: safeNonNegativeInteger(alignmentData?.organizationCount)
    },
    alignment: sanitizedAlignment(alignmentData),
    operation: {
      operationKeyDigest: isFullFingerprint(operation?.operationKeyDigest) ? operation.operationKeyDigest : null,
      requestFingerprintDigest: isFullFingerprint(operation?.requestFingerprintDigest)
        ? operation.requestFingerprintDigest
        : null,
      idempotencyKeyDigest,
      mode: operation?.mode === "candidate-materialization" ? operation.mode : null,
      status: operation?.status === "completed" ? operation.status : operation?.status === "failed" ? operation.status : null,
      legacyStatus: operation?.legacyStatus === "read-only" ? operation.legacyStatus : null,
      identityStatus: CANDIDATE_IDENTITY_STATUSES.includes(operation?.identityStatus)
        ? operation.identityStatus
        : operation?.identityStatus === null || operation?.identityStatus === undefined
          ? null
          : "unexpected-non-null",
      compensationStatus: isKnownLedgerCompensationStatus(operation?.compensationStatus)
        ? operation.compensationStatus
        : null,
      errorCode: operation?.errorCode === null ? null : operation?.errorCode ? "unexpected-non-null" : null
    },
    ledger,
    failures
  };
}

function assertHealth(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateMaterializationGateOptions,
  label = "health"
): void {
  requireEqual(failures, `${label} HTTP status`, response.status, 200);
  requireEqual(failures, `${label} status`, response.body.status, "ok");
  requireEqual(failures, `${label} service`, response.body.service, "identity-adapter");
  requirePattern(failures, `${label} revision`, response.body.revision, FULL_REVISION);
  if (options.expectedRevision) requireEqual(failures, `${label} revision`, response.body.revision, options.expectedRevision);
  const posture = response.body.capabilities?.organizationWrite;
  requireEqual(failures, `${label} organization mode`, posture?.mode, "disabled");
  requireEqual(failures, `${label} route integration`, posture?.routeIntegrationEnabled, false);
  requireEqual(failures, `${label} dual-write execution`, posture?.dualWriteExecutionEnabled, false);
  requireEqual(failures, `${label} materialization enabled`, posture?.candidateMaterializationEnabled, options.apply);
  requireEqual(failures, `${label} materialization target configured`, posture?.candidateMaterializationTargetConfigured, true);
  requireEqual(failures, `${label} batch materialization enabled`, posture?.candidateBatchMaterializationEnabled, false);
  requireEqual(failures, `${label} batch materialization environment`, posture?.candidateBatchMaterializationEnvironment, "disabled");
  requireEqual(failures, `${label} rollout mode`, posture?.rolloutMode, "off");
  requireEqual(failures, `${label} rollout allowlist count`, posture?.rolloutAllowlistCount, 0);
  requireEqual(failures, `${label} rollout percentage`, posture?.rolloutPercentage, 0);
  requireEqual(failures, `${label} source of truth`, posture?.sourceOfTruth, "legacy");
  requireEqual(failures, `${label} identity native support`, posture?.identityNativeSupported, false);
}

function assertRestoredHealth(
  failures: string[],
  response: JsonResponse,
  options: OrganizationCandidateMaterializationGateOptions
): void {
  requireEqual(failures, "restored health HTTP status", response.status, 200);
  requireEqual(failures, "restored health status", response.body.status, "ok");
  requireEqual(failures, "restored health service", response.body.service, "identity-adapter");
  requirePattern(failures, "restored health revision", response.body.revision, FULL_REVISION);
  requireEqual(failures, "restored health revision", response.body.revision, options.expectedRevision);
  const posture = response.body.capabilities?.organizationWrite;
  requireEqual(failures, "restored health organization mode", posture?.mode, "disabled");
  requireEqual(failures, "restored health route integration", posture?.routeIntegrationEnabled, false);
  requireEqual(failures, "restored health dual-write execution", posture?.dualWriteExecutionEnabled, false);
  requireEqual(failures, "restored health materialization enabled", posture?.candidateMaterializationEnabled, false);
  requireEqual(failures, "restored health materialization target configured", posture?.candidateMaterializationTargetConfigured, false);
  requireEqual(failures, "restored health batch materialization enabled", posture?.candidateBatchMaterializationEnabled, false);
  requireEqual(failures, "restored health batch materialization environment", posture?.candidateBatchMaterializationEnvironment, "disabled");
  requireEqual(failures, "restored health rollout mode", posture?.rolloutMode, "off");
  requireEqual(failures, "restored health rollout allowlist count", posture?.rolloutAllowlistCount, 0);
  requireEqual(failures, "restored health rollout percentage", posture?.rolloutPercentage, 0);
  requireEqual(failures, "restored health source of truth", posture?.sourceOfTruth, "legacy");
  requireEqual(failures, "restored health identity native support", posture?.identityNativeSupported, false);
}

function assertReadiness(failures: string[], readiness: Record<string, any> | undefined, apply: boolean): void {
  requireEqual(failures, "readiness enabled", readiness?.enabled, false);
  requireEqual(failures, "readiness mode", readiness?.mode, "disabled");
  requireEqual(failures, "readiness route integration", readiness?.routeIntegrationEnabled, false);
  requireEqual(failures, "readiness route", readiness?.route, "/v1/plugin-user/update-user");
  requireEqual(failures, "readiness scope", readiness?.scope, "membership-replace");
  requireEqual(failures, "readiness source of truth", readiness?.sourceOfTruth, "legacy");
  requireEqual(failures, "readiness repository configured", readiness?.repositoryConfigured, true);
  requireEqual(failures, "readiness dual-write execution", readiness?.dualWriteExecutionEnabled, false);
  requireEqual(failures, "readiness identity native support", readiness?.identityNativeSupported, false);
  requireEqual(failures, "readiness rollout mode", readiness?.rollout?.mode, "off");
  requireEqual(failures, "readiness rollout allowlist count", readiness?.rollout?.allowlistCount, 0);
  requireEqual(failures, "readiness rollout percentage", readiness?.rollout?.percentage, 0);
  requireEqual(failures, "readiness rollout selection configured", readiness?.rollout?.selectionConfigured, false);
  requireArrayEqual(failures, "readiness blocked reasons", readiness?.blockedReasons, []);

  const materialization = readiness?.candidateMaterialization;
  requireEqual(failures, "readiness materialization enabled", materialization?.enabled, apply);
  requireEqual(failures, "readiness materialization target configured", materialization?.targetConfigured, true);
  requireEqual(failures, "readiness materialization schema", materialization?.schemaReady, true);
  requireEqual(failures, "readiness materialization preview", materialization?.canPreview, true);
  requireEqual(failures, "readiness materialization apply", materialization?.canApply, apply);
  requireArrayEqual(
    failures,
    "readiness materialization blockers",
    materialization?.blockers,
    apply ? [] : ["candidate-materialization-disabled"]
  );
  requireEqual(failures, "readiness internal token requirement", materialization?.requiresInternalToken, true);
  requireEqual(failures, "readiness fingerprint requirement", materialization?.requiresExpectedSnapshotFingerprint, true);
  requireEqual(failures, "readiness idempotency requirement", materialization?.requiresIdempotencyKey, true);
  requireEqual(failures, "readiness materialization source", materialization?.sourceOfTruth, "legacy");
  requireEqual(failures, "readiness legacy mutation", materialization?.mutatesLegacy, false);
  requireEqual(failures, "readiness materialization write scope", materialization?.writeScope, "identity-candidate-only");
  const batch = readiness?.candidateBatchMaterialization;
  requireEqual(failures, "readiness batch materialization enabled", batch?.enabled, false);
  requireEqual(failures, "readiness batch materialization environment", batch?.environment, "disabled");
  requireEqual(failures, "readiness batch materialization apply", batch?.canApply, false);
  requireEqual(failures, "readiness batch protected subject writes", batch?.protectedSubjectsWritten, false);
}

function assertRestoredReadiness(failures: string[], readiness: Record<string, any> | undefined): void {
  requireEqual(failures, "restored readiness enabled", readiness?.enabled, false);
  requireEqual(failures, "restored readiness mode", readiness?.mode, "disabled");
  requireEqual(failures, "restored readiness route integration", readiness?.routeIntegrationEnabled, false);
  requireEqual(failures, "restored readiness route", readiness?.route, "/v1/plugin-user/update-user");
  requireEqual(failures, "restored readiness scope", readiness?.scope, "membership-replace");
  requireEqual(failures, "restored readiness source of truth", readiness?.sourceOfTruth, "legacy");
  requireEqual(failures, "restored readiness repository configured", readiness?.repositoryConfigured, true);
  requireEqual(failures, "restored readiness dual-write execution", readiness?.dualWriteExecutionEnabled, false);
  requireEqual(failures, "restored readiness identity native support", readiness?.identityNativeSupported, false);
  requireEqual(failures, "restored readiness rollout mode", readiness?.rollout?.mode, "off");
  requireEqual(failures, "restored readiness rollout allowlist count", readiness?.rollout?.allowlistCount, 0);
  requireEqual(failures, "restored readiness rollout percentage", readiness?.rollout?.percentage, 0);
  requireEqual(failures, "restored readiness rollout selection configured", readiness?.rollout?.selectionConfigured, false);
  requireArrayEqual(failures, "restored readiness blocked reasons", readiness?.blockedReasons, []);

  const materialization = readiness?.candidateMaterialization;
  requireEqual(failures, "restored readiness materialization enabled", materialization?.enabled, false);
  requireEqual(failures, "restored readiness materialization target configured", materialization?.targetConfigured, false);
  requireEqual(failures, "restored readiness materialization schema", materialization?.schemaReady, true);
  requireEqual(failures, "restored readiness materialization preview", materialization?.canPreview, false);
  requireEqual(failures, "restored readiness materialization apply", materialization?.canApply, false);
  requireArrayEqual(
    failures,
    "restored readiness materialization blockers",
    materialization?.blockers,
    ["target-not-configured", "candidate-materialization-disabled"]
  );
  requireEqual(failures, "restored readiness internal token requirement", materialization?.requiresInternalToken, true);
  requireEqual(failures, "restored readiness fingerprint requirement", materialization?.requiresExpectedSnapshotFingerprint, true);
  requireEqual(failures, "restored readiness idempotency requirement", materialization?.requiresIdempotencyKey, true);
  requireEqual(failures, "restored readiness materialization source", materialization?.sourceOfTruth, "legacy");
  requireEqual(failures, "restored readiness legacy mutation", materialization?.mutatesLegacy, false);
  requireEqual(failures, "restored readiness materialization write scope", materialization?.writeScope, "identity-candidate-only");
  const batch = readiness?.candidateBatchMaterialization;
  requireEqual(failures, "restored readiness batch materialization enabled", batch?.enabled, false);
  requireEqual(failures, "restored readiness batch materialization environment", batch?.environment, "disabled");
  requireEqual(failures, "restored readiness batch materialization apply", batch?.canApply, false);
  requireEqual(failures, "restored readiness batch protected subject writes", batch?.protectedSubjectsWritten, false);
}

function assertPreview(
  failures: string[],
  preview: Record<string, any> | undefined,
  alignment: Record<string, any> | undefined,
  options: OrganizationCandidateMaterializationGateOptions
): void {
  requireEqual(failures, "preview mutation", preview?.mutation, false);
  requireEqual(failures, "preview executable", preview?.executable, options.apply);
  requirePattern(failures, "preview target fingerprint", preview?.targetFingerprint, SHORT_FINGERPRINT);
  requireEqual(
    failures,
    "preview exact target fingerprint",
    preview?.targetFingerprint,
    shortDigest(`legacy:${options.legacyUserId}`)
  );
  requirePattern(failures, "preview snapshot fingerprint", preview?.expectedSnapshotFingerprint, FULL_FINGERPRINT);
  if (options.apply) {
    requireEqual(
      failures,
      "preview reviewed snapshot fingerprint",
      preview?.expectedSnapshotFingerprint,
      options.expectedSnapshotFingerprint
    );
  }
  requireEqual(failures, "preview unresolved operation count", preview?.unresolvedOperationCount, 0);
  requireEqual(failures, "preview source of truth", preview?.sourceOfTruth, "legacy");
  requireEqual(failures, "preview legacy write", preview?.legacyWritePerformed, false);
  requireEqual(failures, "preview identity candidate write", preview?.identityCandidateWritePerformed, false);
  requireArrayEqual(
    failures,
    "preview blocked reasons",
    preview?.blockedReasons,
    options.apply ? [] : ["candidate-materialization-disabled"]
  );
  requireNonNegativeInteger(failures, "preview organization count", preview?.organizationCount);
  assertMissingCandidateAlignment(
    failures,
    "preview alignment",
    preview?.alignment,
    preview?.organizationCount
  );
  assertExactSubjectAlignment(
    failures,
    "preflight alignment",
    alignment,
    options.legacyUserId,
    preview?.expectedSnapshotFingerprint,
    preview?.organizationCount,
    false
  );
  requireEqual(failures, "preview/alignment organization count", alignment?.organizationCount, preview?.organizationCount);
}

function assertApplyResponse(
  failures: string[],
  data: Record<string, any> | undefined,
  preview: Record<string, any> | undefined,
  expectedSnapshotFingerprint: string,
  expectedOrganizationCount: unknown
): void {
  requireBoolean(failures, "apply materialized", data?.materialized);
  requireBoolean(failures, "apply idempotent replay", data?.idempotentReplay);
  if (typeof data?.materialized === "boolean" && typeof data?.idempotentReplay === "boolean") {
    requireEqual(failures, "apply materialized/replay exclusivity", data.materialized !== data.idempotentReplay, true);
  }
  requirePattern(failures, "apply operation digest", data?.operationKeyDigest, SHORT_FINGERPRINT);
  requireEqual(failures, "apply target fingerprint", data?.subjectFingerprint, preview?.targetFingerprint);
  requireEqual(failures, "apply snapshot fingerprint", data?.snapshotFingerprint, shortDigest(expectedSnapshotFingerprint));
  requireNonNegativeInteger(failures, "apply organization count", data?.organizationCount);
  requireEqual(failures, "apply organization count", data?.organizationCount, expectedOrganizationCount);
  assertMissingCandidateAlignment(failures, "apply before alignment", data?.before, expectedOrganizationCount);
  assertZeroAlignment(failures, "apply after alignment", data?.after, expectedOrganizationCount);
  const safety = data?.safety;
  requireEqual(failures, "apply safety legacy write", safety?.legacyWritePerformed, false);
  requireEqual(failures, "apply safety identity candidate write", safety?.identityCandidateWritePerformed, data?.materialized);
  requireEqual(failures, "apply safety historical replay", safety?.historicalMutationReplayed, false);
  requireEqual(failures, "apply safety Legacy authority", safety?.legacyRemainsAuthoritative, true);
  requireEqual(failures, "apply safety AuthZ input", safety?.authzInputChanged, false);
  requireEqual(failures, "apply safety write scope", safety?.writeScope, "identity-candidate-only");
}

function assertMissingCandidateAlignment(
  failures: string[],
  label: string,
  alignment: Record<string, any> | undefined,
  expectedOrganizationCount: unknown
): void {
  requireEqual(failures, `${label} aligned`, alignment?.aligned, false);
  requireEqual(failures, `${label} P0`, alignment?.P0, 0);
  requirePositiveInteger(failures, `${label} P1`, alignment?.P1);
  requireEqual(failures, `${label} P2`, alignment?.P2, 0);
  requirePositiveInteger(failures, `${label} mismatch`, alignment?.mismatch);
  requireEqual(failures, `${label} P1/mismatch`, alignment?.P1, alignment?.mismatch);
  requireEqual(failures, `${label} reason`, alignment?.reason, "identity-candidate-snapshot-missing");
  requireNonNegativeInteger(failures, `${label} organization count`, alignment?.organizationCount);
  requireEqual(failures, `${label} organization count`, alignment?.organizationCount, expectedOrganizationCount);
}

function assertZeroAlignment(
  failures: string[],
  label: string,
  alignment: Record<string, any> | undefined,
  expectedOrganizationCount: unknown
): void {
  requireEqual(failures, `${label} aligned`, alignment?.aligned, true);
  requireEqual(failures, `${label} P0`, alignment?.P0, 0);
  requireEqual(failures, `${label} P1`, alignment?.P1, 0);
  requireEqual(failures, `${label} P2`, alignment?.P2, 0);
  requireEqual(failures, `${label} mismatch`, alignment?.mismatch, 0);
  requireNullish(failures, `${label} reason`, alignment?.reason);
  requireNonNegativeInteger(failures, `${label} organization count`, alignment?.organizationCount);
  requireEqual(failures, `${label} organization count`, alignment?.organizationCount, expectedOrganizationCount);
}

function assertExactSubjectAlignment(
  failures: string[],
  label: string,
  alignment: Record<string, any> | undefined,
  legacyUserId: number,
  expectedSnapshotFingerprint: unknown,
  expectedOrganizationCount: unknown,
  expectAligned: boolean
): void {
  requireEqual(failures, `${label} exact subject`, alignment?.legacyUserId, legacyUserId);
  requireEqual(failures, `${label} source of truth`, alignment?.sourceOfTruth, "legacy");
  requireEqual(failures, `${label} snapshot fingerprint`, alignment?.legacySnapshotFingerprint, expectedSnapshotFingerprint);
  if (expectAligned) assertZeroAlignment(failures, label, alignment, expectedOrganizationCount);
  else assertMissingCandidateAlignment(failures, label, alignment, expectedOrganizationCount);
}

function inspectLedger(
  failures: string[],
  label: string,
  summary: Record<string, any> | undefined,
  recent: Record<string, any> | undefined,
  expectedSinceMinutes: number
) {
  requireEqual(failures, `${label} summary configured`, summary?.configured, true);
  requireEqual(failures, `${label} summary schema`, summary?.schemaReady, true);
  requireEqual(failures, `${label} summary since minutes`, summary?.sinceMinutes, expectedSinceMinutes);
  requireEqual(failures, `${label} recent configured`, recent?.configured, true);
  requireEqual(failures, `${label} recent schema`, recent?.schemaReady, true);
  requireEqual(failures, `${label} recent since minutes`, recent?.sinceMinutes, expectedSinceMinutes);
  requireEqual(failures, `${label} recent limit`, recent?.limit, 200);

  const summaryOperations = Array.isArray(summary?.operations) ? summary.operations : null;
  const recentOperations = Array.isArray(recent?.operations) ? recent.operations : null;
  if (!summaryOperations) failures.push(`${label} summary operations assertion failed`);
  if (!recentOperations) failures.push(`${label} recent operations assertion failed`);

  let operationCount = 0;
  let summaryUnresolvedOperationCount = 0;
  let malformedOperationCount = summaryOperations ? 0 : 1;
  const summaryGroups = new Map<string, { total: number; firstRequestedAt: string; lastRequestedAt: string }>();
  for (const [index, operation] of (summaryOperations ?? []).entries()) {
    let valid = isPlainRecord(operation);
    const total = Number.isSafeInteger(operation?.total) && Number(operation.total) > 0
      ? Number(operation.total)
      : null;
    if (total === null) {
      failures.push(`${label} summary operation ${index} total assertion failed`);
      valid = false;
    } else {
      operationCount += total;
      if (!isResolvedLedgerState(operation?.status, operation?.compensationStatus)) {
        summaryUnresolvedOperationCount += total;
      }
    }
    if (!isKnownLedgerMode(operation?.mode)) {
      failures.push(`${label} summary operation ${index} mode assertion failed`);
      valid = false;
    }
    if (!isKnownLedgerStatus(operation?.status)) {
      failures.push(`${label} summary operation ${index} status assertion failed`);
      valid = false;
    }
    if (!isKnownLedgerCompensationStatus(operation?.compensationStatus)) {
      failures.push(`${label} summary operation ${index} compensation status assertion failed`);
      valid = false;
    }
    if (!isValidLedgerSummaryState(operation?.mode, operation?.status, operation?.compensationStatus)) {
      failures.push(`${label} summary operation ${index} mode-specific state assertion failed`);
      valid = false;
    }
    if (!isCanonicalTimestamp(operation?.firstRequestedAt) || !isCanonicalTimestamp(operation?.lastRequestedAt)) {
      failures.push(`${label} summary operation ${index} timestamps assertion failed`);
      valid = false;
    } else if (operation.firstRequestedAt > operation.lastRequestedAt) {
      failures.push(`${label} summary operation ${index} timestamp order assertion failed`);
      valid = false;
    }
    if (valid && total !== null) {
      const groupKey = ledgerGroupKey(operation.mode, operation.status, operation.compensationStatus);
      if (summaryGroups.has(groupKey)) {
        failures.push(`${label} summary operation ${index} duplicate group assertion failed`);
        valid = false;
      } else {
        summaryGroups.set(groupKey, {
          total,
          firstRequestedAt: operation.firstRequestedAt,
          lastRequestedAt: operation.lastRequestedAt
        });
      }
    }
    if (!valid) malformedOperationCount += 1;
  }

  let recentUnresolvedOperationCount = 0;
  const recentGroups = new Map<string, { total: number; firstRequestedAt: string; lastRequestedAt: string }>();
  for (const [index, operation] of (recentOperations ?? []).entries()) {
    let valid = isPlainRecord(operation);
    if (!isFullFingerprint(operation?.operationKeyDigest)) {
      failures.push(`${label} recent operation ${index} operation digest assertion failed`);
      valid = false;
    }
    if (!isFullFingerprint(operation?.idempotencyKeyDigest)) {
      failures.push(`${label} recent operation ${index} idempotency digest assertion failed`);
      valid = false;
    }
    if (!isFullFingerprint(operation?.requestFingerprintDigest)) {
      failures.push(`${label} recent operation ${index} request fingerprint digest assertion failed`);
      valid = false;
    }
    if (!Number.isSafeInteger(operation?.legacyUserId) || Number(operation.legacyUserId) <= 0) {
      failures.push(`${label} recent operation ${index} subject assertion failed`);
      valid = false;
    }
    if (!isKnownLedgerMode(operation?.mode)) {
      failures.push(`${label} recent operation ${index} mode assertion failed`);
      valid = false;
    }
    if (!isKnownLedgerStatus(operation?.status)) {
      failures.push(`${label} recent operation ${index} status assertion failed`);
      valid = false;
    }
    if (!isKnownLedgerCompensationStatus(operation?.compensationStatus)) {
      failures.push(`${label} recent operation ${index} compensation status assertion failed`);
      valid = false;
    }
    for (const field of ["legacyStatus", "identityStatus", "errorCode"] as const) {
      if (!hasOwn(operation, field) || !isNullableNonEmptyString(operation?.[field])) {
        failures.push(`${label} recent operation ${index} ${field} assertion failed`);
        valid = false;
      }
    }
    if (!isCanonicalTimestamp(operation?.requestedAt)) {
      failures.push(`${label} recent operation ${index} requested timestamp assertion failed`);
      valid = false;
    }
    const terminal = operation?.status === "completed" || operation?.status === "failed";
    if (terminal ? !isCanonicalTimestamp(operation?.completedAt) : operation?.completedAt !== null) {
      failures.push(`${label} recent operation ${index} completed timestamp assertion failed`);
      valid = false;
    }
    if (
      terminal &&
      isCanonicalTimestamp(operation?.requestedAt) &&
      isCanonicalTimestamp(operation?.completedAt) &&
      operation.completedAt < operation.requestedAt
    ) {
      failures.push(`${label} recent operation ${index} timestamp order assertion failed`);
      valid = false;
    }
    if (!isPlainRecord(operation?.metadata)) {
      failures.push(`${label} recent operation ${index} metadata assertion failed`);
      valid = false;
    }
    if (!isValidLedgerRecentState(operation)) {
      failures.push(`${label} recent operation ${index} mode-specific state assertion failed`);
      valid = false;
    }
    if (!isResolvedLedgerState(operation?.status, operation?.compensationStatus)) {
      recentUnresolvedOperationCount += 1;
    }
    if (!valid) {
      malformedOperationCount += 1;
      if (isResolvedLedgerState(operation?.status, operation?.compensationStatus)) {
        recentUnresolvedOperationCount += 1;
      }
      continue;
    }
    const groupKey = ledgerGroupKey(operation.mode, operation.status, operation.compensationStatus);
    const existing = recentGroups.get(groupKey);
    if (existing) {
      existing.total += 1;
      if (operation.requestedAt < existing.firstRequestedAt) existing.firstRequestedAt = operation.requestedAt;
      if (operation.requestedAt > existing.lastRequestedAt) existing.lastRequestedAt = operation.requestedAt;
    } else {
      recentGroups.set(groupKey, {
        total: 1,
        firstRequestedAt: operation.requestedAt,
        lastRequestedAt: operation.requestedAt
      });
    }
  }

  const recentOperationCount = recentOperations?.length ?? null;
  let aggregateMismatch = false;
  if (recentOperationCount === null || operationCount !== recentOperationCount) {
    failures.push(`${label} summary total/recent length assertion failed`);
    aggregateMismatch = true;
  }
  if (summaryGroups.size !== recentGroups.size) {
    failures.push(`${label} summary/recent group count assertion failed`);
    aggregateMismatch = true;
  }
  for (const [groupKey, group] of summaryGroups) {
    const recentGroup = recentGroups.get(groupKey);
    if (
      !recentGroup ||
      recentGroup.total !== group.total ||
      recentGroup.firstRequestedAt !== group.firstRequestedAt ||
      recentGroup.lastRequestedAt !== group.lastRequestedAt
    ) {
      failures.push(`${label} summary/recent group assertion failed`);
      aggregateMismatch = true;
    }
  }

  return {
    configured: summary?.configured === true && recent?.configured === true,
    schemaReady: summary?.schemaReady === true && recent?.schemaReady === true,
    operationCount,
    recentOperationCount,
    unresolvedOperationCount: Math.max(
      summaryUnresolvedOperationCount,
      recentUnresolvedOperationCount,
      malformedOperationCount > 0 || aggregateMismatch ? 1 : 0
    )
  };
}

function assertInternalEnvelope(
  failures: string[],
  label: string,
  response: JsonResponse,
  capability: string,
  expectedStatus = 200
): void {
  requireEqual(failures, `${label} HTTP status`, response.status, expectedStatus);
  requireEqual(failures, `${label} status`, response.body.status, "ok");
  requireEqual(failures, `${label} service`, response.body.service, "identity-adapter");
  requireEqual(failures, `${label} capability`, response.body.capability, capability);
}

function sanitizedPreflight(preflight: ReadOnlyPreflight, expectedSinceMinutes: number) {
  const healthBody = preflight.health.body;
  const posture = healthBody.capabilities?.organizationWrite;
  const readiness = preflight.readiness.body.data;
  const preview = preflight.preview?.body.data;
  const alignment = preflight.alignment?.body.data;
  const ledgerFailures: string[] = [];
  const ledger = preflight.summary && preflight.recent
    ? inspectLedger(
      ledgerFailures,
      "output ledger",
      preflight.summary.body.data,
      preflight.recent.body.data,
      expectedSinceMinutes
    )
    : null;
  return {
    revision: FULL_REVISION.test(String(healthBody.revision ?? "")) ? healthBody.revision : null,
    posture: {
      mode: posture?.mode === "disabled" ? "disabled" : null,
      routeIntegrationEnabled: posture?.routeIntegrationEnabled === true,
      dualWriteExecutionEnabled: posture?.dualWriteExecutionEnabled === true,
      candidateMaterializationEnabled: posture?.candidateMaterializationEnabled === true,
      candidateMaterializationTargetConfigured: posture?.candidateMaterializationTargetConfigured === true,
      rolloutMode: posture?.rolloutMode === "off" ? "off" : null,
      rolloutAllowlistCount: safeNonNegativeInteger(posture?.rolloutAllowlistCount),
      rolloutPercentage: safeNonNegativeInteger(posture?.rolloutPercentage),
      sourceOfTruth: posture?.sourceOfTruth === "legacy" ? "legacy" : null,
      identityNativeSupported: posture?.identityNativeSupported === true
    },
    readiness: {
      repositoryConfigured: readiness?.repositoryConfigured === true,
      materialization: {
        enabled: readiness?.candidateMaterialization?.enabled === true,
        targetConfigured: readiness?.candidateMaterialization?.targetConfigured === true,
        schemaReady: readiness?.candidateMaterialization?.schemaReady === true,
        canPreview: readiness?.candidateMaterialization?.canPreview === true,
        canApply: readiness?.candidateMaterialization?.canApply === true,
        blockerCount: Array.isArray(readiness?.candidateMaterialization?.blockers)
          ? readiness.candidateMaterialization.blockers.length
          : null
      }
    },
    target: preview ? {
      fingerprint: isShortFingerprint(preview.targetFingerprint) ? preview.targetFingerprint : null,
      snapshotFingerprint: isFullFingerprint(preview.expectedSnapshotFingerprint)
        ? preview.expectedSnapshotFingerprint
        : null,
      organizationCount: safeNonNegativeInteger(preview.organizationCount)
    } : null,
    preview: preview ? {
      executable: preview.executable === true,
      mutation: preview.mutation === true,
      unresolvedOperationCount: safeNonNegativeInteger(preview.unresolvedOperationCount),
      alignment: sanitizedAlignment(preview.alignment)
    } : null,
    alignment: sanitizedAlignment(alignment),
    ledgerBefore: ledger
  };
}

function sanitizedAlignment(value: Record<string, any> | undefined) {
  if (!value || typeof value !== "object") return null;
  return {
    aligned: value.aligned === true,
    mismatch: safeNonNegativeInteger(value.mismatch),
    P0: safeNonNegativeInteger(value.P0),
    P1: safeNonNegativeInteger(value.P1),
    P2: safeNonNegativeInteger(value.P2),
    reason: value.reason === null || value.reason === undefined
      ? null
      : value.reason === "identity-candidate-snapshot-missing"
        ? value.reason
        : "unexpected-non-null",
    organizationCount: safeNonNegativeInteger(value.organizationCount)
  };
}

function sanitizedSafety(value: Record<string, any> | undefined) {
  if (!value || typeof value !== "object") return null;
  return {
    legacyWritePerformed: value.legacyWritePerformed === true,
    identityCandidateWritePerformed: value.identityCandidateWritePerformed === true,
    historicalMutationReplayed: value.historicalMutationReplayed === true,
    legacyRemainsAuthoritative: value.legacyRemainsAuthoritative === true,
    authzInputChanged: value.authzInputChanged === true,
    writeScope: value.writeScope === "identity-candidate-only" ? value.writeScope : null
  };
}

function validateOptions(options: OrganizationCandidateMaterializationGateOptions): { base: string } {
  if (!options.token?.trim()) throw new Error(`${INTERNAL_TOKEN_ENV} or IDENTITY_INTERNAL_API_TOKEN is required.`);
  const selectedModes = Number(options.apply) + Number(options.expectRestored === true) + Number(options.verifyOutcome === true);
  if (selectedModes > 1) {
    throw new Error("--apply, --expect-restored, and --verify-outcome are mutually exclusive.");
  }
  if (!options.expectRestored && (!Number.isSafeInteger(options.legacyUserId) || options.legacyUserId <= 0)) {
    throw new Error("legacy-user-id must be a positive integer.");
  }
  if (!Number.isSafeInteger(options.sinceMinutes) || options.sinceMinutes < 1 || options.sinceMinutes > 1440) {
    throw new Error("since-minutes must be an integer from 1 to 1440.");
  }
  const base = loopbackBaseUrl(options.adapterUrl);
  if (!options.expectedRevision) {
    throw new Error("--expected-revision with a full 40-character Git SHA is required in every mode.");
  }
  if (!FULL_REVISION.test(options.expectedRevision)) {
    throw new Error("expected-revision must be a full 40-character Git SHA.");
  }
  if (options.expectedSnapshotFingerprint !== undefined && !FULL_FINGERPRINT.test(options.expectedSnapshotFingerprint)) {
    throw new Error("expected-snapshot-fingerprint must be a 64-character hexadecimal fingerprint.");
  }
  if (options.expectRestored) {
    if (options.legacyUserId !== 0) {
      throw new Error("--expect-restored does not accept --legacy-user-id because restoration is subject-independent.");
    }
    if (options.expectedSnapshotFingerprint !== undefined) {
      throw new Error("--expect-restored does not accept --expected-snapshot-fingerprint.");
    }
    return { base };
  }
  if (options.verifyOutcome) {
    if (!options.expectedSnapshotFingerprint) {
      throw new Error("--verify-outcome requires --expected-snapshot-fingerprint with the reviewed fingerprint.");
    }
    options.idempotencyKey = validIdempotencyKey(options.idempotencyKey, "--verify-outcome");
    return { base };
  }
  if (options.apply) {
    if (!options.expectedSnapshotFingerprint) {
      throw new Error("--apply requires --expected-snapshot-fingerprint with the reviewed fingerprint.");
    }
    options.idempotencyKey = validIdempotencyKey(options.idempotencyKey, "--apply");
  }
  if (!options.apply && options.expectedSnapshotFingerprint !== undefined) {
    throw new Error("Preview mode does not accept --expected-snapshot-fingerprint.");
  }
  return { base };
}

function validIdempotencyKey(value: string | null, mode: "--apply" | "--verify-outcome"): string {
  const key = value?.trim() ?? "";
  if (!key || key.length > 180 || /[\u0000-\u001f\u007f]/.test(key)) {
    throw new Error(`${mode} requires a valid 1-180 character ${IDEMPOTENCY_KEY_ENV}.`);
  }
  return key;
}

function loopbackBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("adapter-url must be a valid loopback HTTP(S) URL.");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !LOOPBACK_HOSTS.has(url.hostname.toLowerCase()) ||
    url.username ||
    url.password ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search ||
    url.hash
  ) {
    throw new Error("adapter-url must use only 127.0.0.1, localhost, or [::1] with no credentials or path.");
  }
  return url.origin;
}

async function requestJson(
  fetcher: typeof fetch,
  label: string,
  url: string,
  init: RequestInit = {},
  expectedStatus = 200
): Promise<JsonResponse> {
  let response: Response;
  try {
    response = await fetcher(url, {
      ...init,
      redirect: "error",
      signal: init.signal ?? AbortSignal.timeout(10_000)
    });
  } catch {
    throw new Error(`${label} request failed.`);
  }
  let body: Record<string, any>;
  try {
    const text = await response.text();
    body = text ? JSON.parse(text) as Record<string, any> : {};
  } catch {
    throw new Error(`${label} returned non-JSON content.`);
  }
  if (response.status !== expectedStatus) throw new Error(`${label} did not return the required HTTP status.`);
  return { status: response.status, body };
}

function requireEqual(failures: string[], label: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) failures.push(`${label} assertion failed`);
}

function requireArrayEqual(failures: string[], label: string, actual: unknown, expected: unknown[]): void {
  if (!Array.isArray(actual) || actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    failures.push(`${label} assertion failed`);
  }
}

function requireOneOf(failures: string[], label: string, actual: unknown, expected: unknown[]): void {
  if (!expected.includes(actual)) failures.push(`${label} assertion failed`);
}

function requirePattern(failures: string[], label: string, actual: unknown, pattern: RegExp): void {
  if (typeof actual !== "string" || !pattern.test(actual)) failures.push(`${label} assertion failed`);
}

function requireBoolean(failures: string[], label: string, actual: unknown): void {
  if (typeof actual !== "boolean") failures.push(`${label} assertion failed`);
}

function requirePositiveInteger(failures: string[], label: string, actual: unknown): void {
  if (!Number.isSafeInteger(actual) || Number(actual) <= 0) failures.push(`${label} assertion failed`);
}

function requireNonNegativeInteger(failures: string[], label: string, actual: unknown): void {
  if (!Number.isSafeInteger(actual) || Number(actual) < 0) failures.push(`${label} assertion failed`);
}

function requireNullish(failures: string[], label: string, actual: unknown): void {
  if (actual !== null && actual !== undefined) failures.push(`${label} assertion failed`);
}

function isKnownLedgerMode(value: unknown): boolean {
  return value === "dual-write" || value === "candidate-materialization";
}

function isKnownLedgerStatus(value: unknown): boolean {
  return value === "pending" || value === "legacy_completed" || value === "completed" || value === "failed";
}

function isKnownLedgerCompensationStatus(value: unknown): boolean {
  return value === "none" || value === "required" || value === "completed" || value === "failed";
}

function isValidLedgerSummaryState(mode: unknown, status: unknown, compensationStatus: unknown): boolean {
  if (mode === "candidate-materialization") {
    return (status === "pending" && compensationStatus === "none") ||
      (status === "completed" && (compensationStatus === "none" || compensationStatus === "completed")) ||
      (status === "failed" && ["none", "required", "failed"].includes(String(compensationStatus)));
  }
  if (mode === "dual-write") {
    return (status === "pending" && compensationStatus === "none") ||
      (status === "legacy_completed" && (compensationStatus === "none" || compensationStatus === "required")) ||
      (status === "completed" && (compensationStatus === "none" || compensationStatus === "completed")) ||
      (status === "failed" && (compensationStatus === "none" || compensationStatus === "failed"));
  }
  return false;
}

function isValidLedgerRecentState(operation: Record<string, any> | undefined): boolean {
  if (!operation) return false;
  const {
    mode,
    status,
    legacyStatus,
    identityStatus,
    compensationStatus,
    errorCode,
    completedAt
  } = operation;
  if (mode === "candidate-materialization") {
    if (legacyStatus !== "read-only") return false;
    if (status === "pending") {
      return identityStatus === "pending" && compensationStatus === "none" && errorCode === null && completedAt === null;
    }
    if (status === "completed") {
      return errorCode === null && isCanonicalTimestamp(completedAt) && (
        (identityStatus === "candidate-materialized" && compensationStatus === "none") ||
        (identityStatus === "candidate-recovered-from-current-legacy" && compensationStatus === "completed")
      );
    }
    if (status === "failed") {
      return isNonEmptyString(errorCode) && isCanonicalTimestamp(completedAt) && (
        (identityStatus === "candidate-materialization-failed" && compensationStatus === "none") ||
        (["candidate-write-outcome-unknown", "candidate-postcheck-failed"].includes(String(identityStatus)) &&
          compensationStatus === "required") ||
        (identityStatus === "candidate-recovery-failed" && compensationStatus === "failed")
      );
    }
    return false;
  }

  if (mode !== "dual-write") return false;
  if (status === "pending") {
    return legacyStatus === null && identityStatus === null && compensationStatus === "none" &&
      errorCode === null && completedAt === null;
  }
  if (status === "legacy_completed") {
    return isLegacySuccessStatus(legacyStatus) && completedAt === null && (
      (identityStatus === "pending" && compensationStatus === "none" && errorCode === null) ||
      (identityStatus === "candidate-failed" && compensationStatus === "required" && isNonEmptyString(errorCode))
    );
  }
  if (status === "completed") {
    return isLegacySuccessStatus(legacyStatus) && errorCode === null && isCanonicalTimestamp(completedAt) && (
      (identityStatus === "candidate-completed" && compensationStatus === "none") ||
      (identityStatus === "candidate-recovered-from-current-legacy" && compensationStatus === "completed")
    );
  }
  if (status === "failed") {
    return isCanonicalTimestamp(completedAt) && isNonEmptyString(errorCode) && (
      ((legacyStatus === "unavailable" || isLegacyFailureStatus(legacyStatus)) &&
        identityStatus === "skipped" && compensationStatus === "none") ||
      (isLegacySuccessStatus(legacyStatus) && identityStatus === "candidate-recovery-failed" &&
        compensationStatus === "failed")
    );
  }
  return false;
}

function ledgerGroupKey(mode: unknown, status: unknown, compensationStatus: unknown): string {
  return `${String(mode)}\u0000${String(status)}\u0000${String(compensationStatus)}`;
}

function isPlainRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(value: unknown, key: string): boolean {
  return isPlainRecord(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function isNullableNonEmptyString(value: unknown): boolean {
  return value === null || isNonEmptyString(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function isLegacySuccessStatus(value: unknown): boolean {
  return typeof value === "string" && /^2\d\d$/.test(value);
}

function isLegacyFailureStatus(value: unknown): boolean {
  return typeof value === "string" && /^[1-5]\d\d$/.test(value) && !isLegacySuccessStatus(value);
}

function isResolvedLedgerState(status: unknown, compensationStatus: unknown): boolean {
  return (status === "completed" && (compensationStatus === "none" || compensationStatus === "completed")) ||
    (status === "failed" && compensationStatus === "none");
}

function safeNonNegativeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
}

function isFullFingerprint(value: unknown): boolean {
  return typeof value === "string" && FULL_FINGERPRINT.test(value);
}

function isShortFingerprint(value: unknown): boolean {
  return typeof value === "string" && SHORT_FINGERPRINT.test(value);
}

function revisionValue(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!FULL_REVISION.test(normalized)) throw new Error("expected-revision must be a full 40-character Git SHA.");
  return normalized;
}

function fingerprintValue(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!FULL_FINGERPRINT.test(normalized)) {
    throw new Error("expected-snapshot-fingerprint must be a 64-character hexadecimal fingerprint.");
  }
  return normalized;
}

function positiveInteger(value: string, name: string): number {
  return boundedInteger(value, name, 1, Number.MAX_SAFE_INTEGER);
}

function boundedInteger(value: string, name: string, min: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}.`);
  }
  return parsed;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function shortDigest(value: string): string {
  return digest(value).slice(0, 16);
}

async function main(): Promise<void> {
  try {
    const result = await runOrganizationCandidateMaterializationGate(
      parseOrganizationCandidateMaterializationGateArgs(process.argv.slice(2))
    );
    console.log(JSON.stringify(result, null, 2));
    if (!result.passed) process.exitCode = 1;
  } catch (error) {
    console.error(JSON.stringify({
      passed: false,
      mode: process.argv.includes("--apply")
        ? "apply"
        : process.argv.includes("--expect-restored")
          ? "expect-restored"
          : process.argv.includes("--verify-outcome")
            ? "verify-outcome"
          : "preview",
      applyAttempted: false,
      outcomeUnknown: false,
      postcheckIncomplete: false,
      failures: [error instanceof Error ? error.message : "candidate materialization gate failed"]
    }, null, 2));
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
