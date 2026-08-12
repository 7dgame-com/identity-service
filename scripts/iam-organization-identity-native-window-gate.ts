import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  runOrganizationWriteWindowGate,
  type OrganizationWriteWindowGateOptions
} from "./iam-organization-write-window-gate.js";
import { writeOrganizationEvidenceExclusive0600 } from "./iam-organization-write-evidence-output.js";

export interface OrganizationIdentityNativeWindowGateOptions {
  adapterUrl: string;
  internalToken: string | null;
  operatorBearerToken: string | null;
  idempotencyKey: string | null;
  legacyUserId: number;
  expectedRevision: string;
  expectedBeforeFingerprint: string;
  expectedAfterFingerprint?: string;
  organizationIds: number[];
  expectedAllowlistCount: number;
  sinceMinutes: number;
  apply: boolean;
  outputPath?: string;
}

const FULL_REVISION = /^[a-f0-9]{40}$/;
const FULL_SHA256 = /^[a-f0-9]{64}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const INTERNAL_TOKEN_ENV = "IDENTITY_IAM_INTERNAL_API_TOKEN";
const OPERATOR_TOKEN_ENV = "IDENTITY_IAM_ORG_NATIVE_WINDOW_OPERATOR_BEARER_TOKEN";
const IDEMPOTENCY_KEY_ENV = "IDENTITY_IAM_ORG_NATIVE_WINDOW_IDEMPOTENCY_KEY";
const ORGANIZATION_IDS_ENV = "IDENTITY_IAM_ORG_NATIVE_WINDOW_ORGANIZATION_IDS";
export const ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT =
  "iam-organization-identity-native-window-gate/v1" as const;

export async function runOrganizationIdentityNativeWindowGate(
  options: OrganizationIdentityNativeWindowGateOptions,
  fetcher: typeof fetch = fetch
) {
  const base = validateOptions(options);
  const preflight = await collectWindowGate(options, fetcher);
  const failures = [...preflight.failures];
  requireEqual(failures, "preflight candidate fingerprint", preflight.candidate?.snapshotFingerprint, options.expectedBeforeFingerprint);
  let desiredSnapshot: Record<string, any> | null = null;
  try {
    desiredSnapshot = await collectDesiredSnapshot(options, base, fetcher);
  } catch {
    failures.push("desired Identity candidate snapshot preview failed; no business POST was attempted");
  }
  requireEqual(failures, "desired snapshot mutation", desiredSnapshot?.mutation, false);
  requireEqual(failures, "desired snapshot source", desiredSnapshot?.sourceOfTruth, "identity-candidate-catalog");
  requireEqual(failures, "desired snapshot organization count", desiredSnapshot?.organizationCount, options.organizationIds.length);
  if (!safeSha(desiredSnapshot?.snapshotFingerprint)) failures.push("desired snapshot fingerprint is not a full SHA-256 digest");
  if (options.apply) {
    requireEqual(failures, "reviewed after fingerprint", desiredSnapshot?.snapshotFingerprint, options.expectedAfterFingerprint);
  }
  if (!options.apply || failures.length > 0) {
    return result(options, {
      passed: failures.length === 0,
      applyAttempted: false,
      outcomeUnknown: false,
      beforeFingerprint: safeSha(preflight.candidate?.snapshotFingerprint),
      afterFingerprint: null,
      desiredFingerprint: safeSha(desiredSnapshot?.snapshotFingerprint),
      operation: null,
      failures
    });
  }

  const idempotencyKey = options.idempotencyKey as string;
  let response: Response;
  try {
    response = await fetcher(`${base}/v1/plugin-user/update-user`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${options.operatorBearerToken as string}`,
        "content-type": "application/json",
        "idempotency-key": idempotencyKey,
        "x-identity-expected-revision": options.expectedRevision
      },
      body: JSON.stringify({ id: options.legacyUserId, organization_ids: options.organizationIds }),
      redirect: "error",
      signal: AbortSignal.timeout(10_000)
    });
  } catch {
    return result(options, {
      passed: false,
      applyAttempted: true,
      outcomeUnknown: true,
      beforeFingerprint: options.expectedBeforeFingerprint,
      afterFingerprint: null,
      desiredFingerprint: safeSha(desiredSnapshot?.snapshotFingerprint),
      operation: { idempotencyKeyDigest: sha256(idempotencyKey), operationKeyDigest: null },
      failures: ["Identity-native POST outcome is unknown; do not retry automatically"]
    });
  }

  const responseBody = await safeJson(response);
  requireEqual(failures, "apply HTTP status", response.status, 200);
  requireEqual(
    failures,
    "apply organization mode header",
    response.headers.get("x-identity-iam-organization-write"),
    "identity-native"
  );
  requireEqual(failures, "apply decision header", response.headers.get("x-identity-iam-organization-write-decision"), "selected:allowlist");
  requireEqual(failures, "apply route header", response.headers.get("x-identity-iam-organization-write-route"), "membership-replace");
  requireEqual(failures, "apply target header", response.headers.get("x-identity-iam-organization-write-target"), sha256(`legacy:${options.legacyUserId}`).slice(0, 16));
  requireEqual(failures, "apply selector header", response.headers.get("x-identity-iam-organization-write-selector-kind"), "allowlist");
  requireEqual(failures, "apply Identity status header", response.headers.get("x-identity-iam-organization-write-identity-status"), "completed");
  requireEqual(failures, "apply body code", responseBody?.code, 0);
  requireEqual(failures, "apply target", responseBody?.data?.id, options.legacyUserId);
  const responseOrganizationIds = Array.isArray(responseBody?.data?.organizations)
    ? responseBody.data.organizations.map((item: unknown) => recordPositiveId(item)).filter((id: number | null): id is number => id !== null)
    : null;
  requireEqual(
    failures,
    "apply organization result count",
    Array.isArray(responseBody?.data?.organizations) ? responseBody.data.organizations.length : null,
    options.organizationIds.length
  );
  requireEqual(
    failures,
    "apply organization set",
    responseOrganizationIds ? JSON.stringify(responseOrganizationIds.sort((a: number, b: number) => a - b)) : null,
    JSON.stringify(options.organizationIds)
  );

  let postcheck;
  try {
    postcheck = await collectWindowGate(options, fetcher);
  } catch {
    return result(options, {
      passed: false,
      applyAttempted: true,
      outcomeUnknown: false,
      beforeFingerprint: options.expectedBeforeFingerprint,
      afterFingerprint: null,
      desiredFingerprint: safeSha(desiredSnapshot?.snapshotFingerprint),
      operation: { idempotencyKeyDigest: sha256(idempotencyKey), operationKeyDigest: null },
      failures: ["Identity-native POST returned but read-only postcheck is incomplete; do not resend POST"]
    });
  }
  failures.push(...postcheck.failures.map((failure: string) => `postcheck: ${failure}`));
  requireEqual(failures, "postcheck candidate fingerprint", postcheck.candidate?.snapshotFingerprint, options.expectedAfterFingerprint);
  requireEqual(failures, "postcheck candidate organization count", postcheck.candidate?.organizationCount, options.organizationIds.length);

  const idempotencyKeyDigest = sha256(idempotencyKey);
  const operations = Array.isArray(postcheck.ledger?.recent?.operations) ? postcheck.ledger.recent.operations : [];
  const matching = operations.filter((operation: Record<string, any>) =>
    operation?.legacyUserId === options.legacyUserId && operation?.idempotencyKeyDigest === idempotencyKeyDigest
  );
  requireEqual(failures, "postcheck matching ledger operation count", matching.length, 1);
  const operation = matching[0];
  const expectedOperationKeyDigest = nativeOperationKeyDigest(options.legacyUserId, idempotencyKey);
  const expectedRequestFingerprintDigest = nativeRequestFingerprintDigest(options.legacyUserId, options.organizationIds);
  requireEqual(failures, "postcheck operation key digest", operation?.operationKeyDigest, expectedOperationKeyDigest);
  requireEqual(failures, "postcheck request fingerprint digest", operation?.requestFingerprintDigest, expectedRequestFingerprintDigest);
  requireEqual(failures, "postcheck ledger mode", operation?.mode, "identity-native");
  requireEqual(failures, "postcheck ledger status", operation?.status, "completed");
  requireEqual(failures, "postcheck Legacy status", operation?.legacyStatus, "not-called");
  requireEqual(failures, "postcheck Identity status", operation?.identityStatus, "completed");
  requireEqual(failures, "postcheck compensation status", operation?.compensationStatus, "none");
  requireEqual(failures, "postcheck error code", operation?.errorCode, null);
  requireEqual(failures, "postcheck Legacy write performed", operation?.metadata?.legacyWritePerformed, false);
  requireEqual(failures, "postcheck owner", operation?.metadata?.owner, "identity");
  requireEqual(failures, "postcheck organization count", operation?.metadata?.organizationCount, options.organizationIds.length);

  return result(options, {
    passed: failures.length === 0,
    applyAttempted: true,
    outcomeUnknown: false,
    beforeFingerprint: options.expectedBeforeFingerprint,
    afterFingerprint: safeSha(postcheck.candidate?.snapshotFingerprint),
    desiredFingerprint: safeSha(desiredSnapshot?.snapshotFingerprint),
    operation: {
      idempotencyKeyDigest,
      operationKeyDigest: safeSha(operation?.operationKeyDigest),
      requestFingerprintDigest: safeSha(operation?.requestFingerprintDigest)
    },
    failures
  });
}

export function parseOrganizationIdentityNativeWindowGateArgs(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env
): OrganizationIdentityNativeWindowGateOptions {
  if (env[ORGANIZATION_IDS_ENV] === undefined) throw new Error(`${ORGANIZATION_IDS_ENV} is required.`);
  const options: OrganizationIdentityNativeWindowGateOptions = {
    adapterUrl: env.IDENTITY_ADAPTER_URL ?? `http://127.0.0.1:${env.PORT ?? "8086"}`,
    internalToken: env[INTERNAL_TOKEN_ENV] ?? env.IDENTITY_INTERNAL_API_TOKEN ?? null,
    operatorBearerToken: env[OPERATOR_TOKEN_ENV] ?? null,
    idempotencyKey: env[IDEMPOTENCY_KEY_ENV] ?? null,
    legacyUserId: 0,
    expectedRevision: "",
    expectedBeforeFingerprint: "",
    organizationIds: parseOrganizationIds(env[ORGANIZATION_IDS_ENV] ?? ""),
    expectedAllowlistCount: 1,
    sinceMinutes: 60,
    apply: false
  };
  for (const arg of argv) {
    if (arg === "--apply") options.apply = true;
    else if (arg.startsWith("--adapter-url=")) options.adapterUrl = arg.slice("--adapter-url=".length).trim();
    else if (arg.startsWith("--legacy-user-id=")) options.legacyUserId = positiveInteger(arg.slice("--legacy-user-id=".length), "legacy-user-id");
    else if (arg.startsWith("--expected-revision=")) options.expectedRevision = normalizedRevision(arg.slice("--expected-revision=".length));
    else if (arg.startsWith("--expected-before-fingerprint=")) options.expectedBeforeFingerprint = normalizedSha(arg.slice("--expected-before-fingerprint=".length), "expected-before-fingerprint");
    else if (arg.startsWith("--expected-after-fingerprint=")) options.expectedAfterFingerprint = normalizedSha(arg.slice("--expected-after-fingerprint=".length), "expected-after-fingerprint");
    else if (arg.startsWith("--expected-allowlist-count=")) options.expectedAllowlistCount = nonNegativeInteger(arg.slice("--expected-allowlist-count=".length), "expected-allowlist-count");
    else if (arg.startsWith("--since-minutes=")) options.sinceMinutes = boundedInteger(arg.slice("--since-minutes=".length), "since-minutes", 1, 1440);
    else if (arg.startsWith("--output=")) options.outputPath = normalizedOutputPath(arg.slice("--output=".length));
    else if (/--(token|operator-token|idempotency-key|organization-ids)=/.test(arg)) {
      throw new Error("Tokens, idempotency keys, and organization IDs must be supplied through the reviewed environment variables.");
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  validateOptions(options);
  return options;
}

async function collectWindowGate(options: OrganizationIdentityNativeWindowGateOptions, fetcher: typeof fetch) {
  const gateOptions: OrganizationWriteWindowGateOptions = {
    adapterUrl: options.adapterUrl,
    token: options.internalToken,
    legacyUserId: options.legacyUserId,
    expectedMode: "identity-native",
    expectedRevision: options.expectedRevision,
    expectedAllowlistCount: options.expectedAllowlistCount,
    sinceMinutes: options.sinceMinutes,
    requireAlignment: false,
    expectedRecoveryDrill: false
  };
  return runOrganizationWriteWindowGate(gateOptions, fetcher);
}

async function collectDesiredSnapshot(
  options: OrganizationIdentityNativeWindowGateOptions,
  base: string,
  fetcher: typeof fetch
): Promise<Record<string, any>> {
  const response = await fetcher(
    `${base}/internal/iam/organization-write/subjects/${options.legacyUserId}/identity-native-snapshot-preview`,
    {
      method: "POST",
      headers: {
        "x-identity-internal-token": options.internalToken as string,
        "content-type": "application/json"
      },
      body: JSON.stringify({ organization_ids: options.organizationIds }),
      redirect: "error",
      signal: AbortSignal.timeout(10_000)
    }
  );
  const body = await safeJson(response);
  if (!response.ok || body?.status !== "ok" ||
    body?.capability !== "iam-organization-write-identity-native-snapshot-preview" ||
    !body.data || typeof body.data !== "object" || Array.isArray(body.data)) {
    throw new Error("invalid desired snapshot preview response");
  }
  return body.data;
}

function validateOptions(options: OrganizationIdentityNativeWindowGateOptions): string {
  if (!options.internalToken) throw new Error(`${INTERNAL_TOKEN_ENV} or IDENTITY_INTERNAL_API_TOKEN is required.`);
  positiveInteger(String(options.legacyUserId), "legacy-user-id");
  normalizedRevision(options.expectedRevision);
  normalizedSha(options.expectedBeforeFingerprint, "expected-before-fingerprint");
  const canonicalIds = [...new Set(options.organizationIds)].sort((left, right) => left - right);
  if (options.organizationIds.some((id) => !Number.isSafeInteger(id) || id <= 0) ||
    JSON.stringify(options.organizationIds) !== JSON.stringify(canonicalIds)) {
    throw new Error("organizationIds must be sorted, unique, positive integers");
  }
  if (options.apply) {
    normalizedSha(options.expectedAfterFingerprint ?? "", "expected-after-fingerprint");
    if (!options.operatorBearerToken) throw new Error(`${OPERATOR_TOKEN_ENV} is required with --apply.`);
    if (!options.idempotencyKey || options.idempotencyKey.length < 16 || options.idempotencyKey.length > 200) {
      throw new Error(`${IDEMPOTENCY_KEY_ENV} must contain 16 to 200 characters with --apply.`);
    }
  }
  let url: URL;
  try { url = new URL(options.adapterUrl); } catch { throw new Error("adapter-url must be an absolute loopback URL"); }
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname.toLowerCase()) || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("adapter-url must be an origin-only HTTP loopback URL without credentials, path, query, or fragment");
  }
  return url.origin;
}

function result<T extends { passed: boolean }>(options: OrganizationIdentityNativeWindowGateOptions, value: T) {
  return {
    contract: ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT,
    environment: "xrteeth-develop" as const,
    scope: "membership-replace" as const,
    mode: options.apply ? "apply" : "preview",
    checkedAt: new Date().toISOString(),
    revision: options.expectedRevision,
    targetFingerprint: sha256(`legacy:${options.legacyUserId}`).slice(0, 16),
    organizationCount: options.organizationIds.length,
    organizationSetSha256: sha256(JSON.stringify(options.organizationIds)),
    ...value
  };
}

async function safeJson(response: Response): Promise<Record<string, any> | null> {
  try {
    const text = await response.text();
    return text ? JSON.parse(text) as Record<string, any> : null;
  } catch { return null; }
}

function parseOrganizationIds(value: string): number[] {
  if (!value.trim()) return [];
  const ids = value.split(",").map((item) => positiveInteger(item.trim(), ORGANIZATION_IDS_ENV));
  return [...new Set(ids)].sort((a, b) => a - b);
}

function recordPositiveId(value: unknown): number | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const descriptor = Object.getOwnPropertyDescriptor(value, "id");
  return descriptor && "value" in descriptor && Number.isSafeInteger(descriptor.value) && descriptor.value > 0
    ? descriptor.value as number
    : null;
}

function requireEqual(failures: string[], field: string, actual: unknown, expected: unknown): void {
  if (actual !== expected) failures.push(`${field} expected ${String(expected)}, got ${String(actual)}`);
}

function normalizedRevision(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!FULL_REVISION.test(normalized)) throw new Error("expected-revision must be a full 40-character Git SHA");
  return normalized;
}

function normalizedSha(value: string, name: string): string {
  const normalized = value.trim().toLowerCase();
  if (!FULL_SHA256.test(normalized)) throw new Error(`${name} must be a full SHA-256 digest`);
  return normalized;
}

function safeSha(value: unknown): string | null {
  return typeof value === "string" && FULL_SHA256.test(value) ? value : null;
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

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizedOutputPath(value: string): string {
  if (!value || value.includes("\0") || !isAbsolute(value) || value !== resolve(value)) {
    throw new Error("output must be a normalized absolute path");
  }
  return value;
}

function nativeOperationKeyDigest(legacyUserId: number, idempotencyKey: string): string {
  const key = `iam-organization-write:v1:membership-replace:${sha256(`${legacyUserId}\u001f${idempotencyKey}`).slice(0, 48)}`;
  return sha256(key);
}

function nativeRequestFingerprintDigest(legacyUserId: number, organizationIds: number[]): string {
  return sha256(sha256(`${legacyUserId}\u001f${organizationIds.join(",")}`));
}

async function main(): Promise<void> {
  const options = parseOrganizationIdentityNativeWindowGateArgs(process.argv.slice(2));
  const output = await runOrganizationIdentityNativeWindowGate(options);
  if (options.outputPath) {
    const written = await writeOrganizationEvidenceExclusive0600(options.outputPath, output);
    process.stdout.write(`${JSON.stringify({ status: output.passed ? "completed" : "blocked", sha256: written.sha256 })}\n`);
  } else process.stdout.write(`${JSON.stringify(output)}\n`);
  if (!output.passed) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
