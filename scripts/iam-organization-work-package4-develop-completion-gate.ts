import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, normalize, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT,
  ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT,
  createOrganizationReconciliationDevelopAuthoritativeCertificateSha256,
  serializeOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCloseout,
  type OrganizationReconciliationDevelopRuntimeVerificationCertificate,
  type OrganizationReconciliationDevelopRuntimeVerificationCloseout
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import { ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT } from "./iam-organization-identity-native-window-gate.js";
import { ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT } from "./iam-organization-write-public-gate.js";

export const ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_MANIFEST_CONTRACT =
  "iam-organization-work-package4-develop-completion-manifest/v1" as const;
export const ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_SUMMARY_CONTRACT =
  "iam-organization-work-package4-develop-completion-summary/v1" as const;
export const ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT =
  "iam-organization-work-package4-develop-regression-summary/v1" as const;

const FULL_REVISION = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const DEVELOP_HEALTH_URL = "https://identity.d.xrteeth.com/health";
const REQUIRED_TEST_FILES = [
  "iam-organization-identity-native.spec.ts",
  "iam-organization-identity-native-window-gate.spec.ts",
  "plugin-user-primary-read-organization-native.spec.ts",
  "iam-organization-reconciliation-develop-full-pipeline.spec.ts",
  "iam-organization-reconciliation-develop-plugin-campus-surfaces.spec.ts",
  "identity-adapter.spec.ts"
] as const;

interface EvidenceRef { path: string; sha256: string }

export interface OrganizationWorkPackage4DevelopCompletionGateReport {
  readonly passed: boolean;
  readonly status: "completed" | "blocked";
  readonly checkedAt: string;
  readonly failures: string[];
  readonly summary: Record<string, unknown> | null;
}

export async function validateOrganizationWorkPackage4DevelopCompletion(
  manifestPath: string,
  now: Date = new Date()
): Promise<OrganizationWorkPackage4DevelopCompletionGateReport> {
  const failures: string[] = [];
  let manifest: Record<string, any> | null = null;
  let manifestBytes: Buffer | null = null;
  try {
    manifestBytes = await readStrictFile(resolve(manifestPath));
    manifest = parseObject(manifestBytes, "manifest", failures);
  } catch {
    failures.push("manifest-file-invalid");
  }
  if (!manifest || !manifestBytes) return report(now, failures, null);

  exactKeys(manifest, [
    "buildRevision", "contract", "environment", "evidence", "governance", "ownerDecision",
    "safety", "task"
  ], "manifest", failures);
  equal(failures, "manifest.contract", manifest.contract, ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_MANIFEST_CONTRACT);
  equal(failures, "manifest.task", manifest.task, "11.1-11.5");
  equal(failures, "manifest.environment", manifest.environment, "xrteeth-develop");
  equal(failures, "manifest.ownerDecision", manifest.ownerDecision, "identity-native");
  pattern(failures, "manifest.buildRevision", manifest.buildRevision, FULL_REVISION);
  validateGovernance(manifest.governance, failures, now);
  validateSafety(manifest.safety, failures);

  const evidence = object(manifest.evidence, "manifest.evidence", failures);
  if (!evidence) return report(now, failures, null);
  exactKeys(evidence, ["defaultOff", "nativeApply", "nativeRestore", "regression", "task72", "task72Certificate"], "manifest.evidence", failures);
  const refs = Object.fromEntries(Object.entries(evidence).map(([name, value]) => [
    name,
    evidenceRef(value, `manifest.evidence.${name}`, failures)
  ])) as Record<string, EvidenceRef | null>;
  const root = dirname(resolve(manifestPath));
  const loaded: Record<string, Record<string, any> | null> = {};
  const resolvedPaths = new Set<string>();
  const digests = new Set<string>();
  for (const [name, ref] of Object.entries(refs)) {
    if (!ref) { loaded[name] = null; continue; }
    try {
      const path = resolveEvidencePath(root, ref.path);
      if (resolvedPaths.has(path)) failures.push(`evidence-path-reused:${name}`);
      resolvedPaths.add(path);
      if (digests.has(ref.sha256)) failures.push(`evidence-digest-reused:${name}`);
      digests.add(ref.sha256);
      const bytes = await readStrictFile(path);
      equal(failures, `evidence.${name}.sha256`, sha256(bytes), ref.sha256);
      loaded[name] = parseObject(bytes, `evidence.${name}`, failures);
    } catch {
      failures.push(`evidence-file-invalid:${name}`);
      loaded[name] = null;
    }
  }

  const task72 = validateTask72(loaded.task72, loaded.task72Certificate, manifest.buildRevision, failures);
  const apply = validateNativeWindow(loaded.nativeApply, "nativeApply", manifest.buildRevision, failures);
  const restore = validateNativeWindow(loaded.nativeRestore, "nativeRestore", manifest.buildRevision, failures);
  validateRestorePair(apply, restore, failures);
  validateFinalReconciliationChronology(task72, restore, failures);
  validateDefaultOff(loaded.defaultOff, manifest.buildRevision, task72, failures);
  const regression = validateRegression(loaded.regression, manifest.buildRevision, failures);

  const summary = failures.length === 0 ? {
    contract: ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_SUMMARY_CONTRACT,
    task: "11.1-11.5",
    environment: "xrteeth-develop",
    status: "develop-complete-production-pending-approval",
    ownerDecision: "identity-native",
    buildRevision: manifest.buildRevision,
    evidence: Object.fromEntries(Object.entries(refs).map(([name, ref]) => [name, ref?.sha256 ?? null])),
    reconciliation: task72,
    nativeWindow: {
      targetFingerprint: apply?.targetFingerprint ?? null,
      forwardOperationKeyDigest: apply?.operation?.operationKeyDigest ?? null,
      restoreOperationKeyDigest: restore?.operation?.operationKeyDigest ?? null,
      beforeFingerprint: apply?.beforeFingerprint ?? null,
      forwardFingerprint: apply?.afterFingerprint ?? null,
      restoredFingerprint: restore?.afterFingerprint ?? null
    },
    regression,
    governance: manifest.governance,
    safety: manifest.safety
  } : null;
  return report(now, failures, summary);
}

function validateTask72(
  value: Record<string, any> | null,
  certificate: Record<string, any> | null,
  revision: unknown,
  failures: string[]
) {
  if (!value || !certificate) return null;
  exactKeys(value, [
    "attestations", "authoritativeCertificateSha256", "closeoutSha256", "contract", "datasets",
    "environment", "mismatchCount", "mode", "outcome", "physicalProbePasses", "safety", "scope",
    "severity", "surfaces", "task"
  ], "task72", failures);
  equal(failures, "task72.contract", value.contract, ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CLOSEOUT_CONTRACT);
  equal(failures, "task72.task", value.task, "7.2");
  equal(failures, "task72.environment", value.environment, "xrteeth-develop");
  equal(failures, "task72.mode", value.mode, "read-only");
  equal(failures, "task72.scope", value.scope, "full-range");
  equal(failures, "task72.outcome", value.outcome, "completed");
  pair(failures, "task72.datasets", value.datasets, 21);
  pair(failures, "task72.surfaces", value.surfaces, 8);
  pair(failures, "task72.attestations", value.attestations, 1);
  pair(failures, "task72.physicalProbePasses", value.physicalProbePasses, 6);
  equal(failures, "task72.severity.P0", value.severity?.P0, 0);
  equal(failures, "task72.severity.P1", value.severity?.P1, 0);
  equal(failures, "task72.severity.P2", value.severity?.P2, 0);
  equal(failures, "task72.mismatchCount", value.mismatchCount, 0);
  pattern(failures, "task72.authoritativeCertificateSha256", value.authoritativeCertificateSha256, SHA256);
  pattern(failures, "task72.closeoutSha256", value.closeoutSha256, SHA256);
  equal(failures, "task72.safety.runtimeSafetyGatePassed", value.safety?.runtimeSafetyGatePassed, false);
  equal(failures, "task72.safety.blocksDualWrite", value.safety?.blocksDualWrite, true);
  equal(failures, "task72.safety.physicalIndependenceVerified", value.safety?.physicalIndependenceVerified, false);
  equal(failures, "task72.safety.productionReady", value.safety?.productionReady, false);
  equal(failures, "task72.safety.productionPromotionAllowed", value.safety?.productionPromotionAllowed, false);
  equal(failures, "task72Certificate.contract", certificate.contract, ORGANIZATION_RECONCILIATION_DEVELOP_RUNTIME_VERIFICATION_CERTIFICATE_CONTRACT);
  equal(failures, "task72Certificate.task", certificate.task, "7.2");
  equal(failures, "task72Certificate.environment", certificate.environment, "xrteeth-develop");
  equal(failures, "task72Certificate.buildRevision", certificate.buildRevision, revision);
  try {
    const typedCertificate = certificate as unknown as OrganizationReconciliationDevelopRuntimeVerificationCertificate;
    const typedCloseout = value as unknown as OrganizationReconciliationDevelopRuntimeVerificationCloseout;
    serializeOrganizationReconciliationDevelopRuntimeCertificate(typedCertificate);
    serializeOrganizationReconciliationDevelopRuntimeCloseout(typedCloseout, typedCertificate);
    equal(
      failures,
      "task72.authoritativeCertificateSha256",
      value.authoritativeCertificateSha256,
      createOrganizationReconciliationDevelopAuthoritativeCertificateSha256(typedCertificate)
    );
  } catch {
    failures.push("task72-certificate-closeout-invalid");
  }
  pattern(failures, "task72Certificate.collection.windowStartedAt", certificate.collection?.windowStartedAt, INSTANT);
  pattern(failures, "task72Certificate.provenance.attestedAt", certificate.provenance?.attestedAt, INSTANT);
  return {
    datasets: "21/21",
    surfaces: "8/8",
    attestations: "1/1",
    physicalProbePasses: "6/6",
    revision,
    windowStartedAt: certificate.collection?.windowStartedAt,
    attestedAt: certificate.provenance?.attestedAt
  };
}

function validateNativeWindow(value: Record<string, any> | null, label: string, revision: unknown, failures: string[]) {
  if (!value) return null;
  exactKeys(value, [
    "afterFingerprint", "applyAttempted", "beforeFingerprint", "checkedAt", "contract", "desiredFingerprint",
    "environment", "failures", "mode", "operation", "organizationCount", "organizationSetSha256",
    "outcomeUnknown", "passed", "revision", "scope", "targetFingerprint"
  ], label, failures);
  equal(failures, `${label}.contract`, value.contract, ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT);
  equal(failures, `${label}.environment`, value.environment, "xrteeth-develop");
  equal(failures, `${label}.scope`, value.scope, "membership-replace");
  equal(failures, `${label}.mode`, value.mode, "apply");
  equal(failures, `${label}.passed`, value.passed, true);
  equal(failures, `${label}.applyAttempted`, value.applyAttempted, true);
  equal(failures, `${label}.outcomeUnknown`, value.outcomeUnknown, false);
  equal(failures, `${label}.revision`, value.revision, revision);
  arrayEmpty(failures, `${label}.failures`, value.failures);
  pattern(failures, `${label}.targetFingerprint`, value.targetFingerprint, /^[a-f0-9]{16}$/);
  pattern(failures, `${label}.organizationSetSha256`, value.organizationSetSha256, SHA256);
  pattern(failures, `${label}.beforeFingerprint`, value.beforeFingerprint, SHA256);
  pattern(failures, `${label}.afterFingerprint`, value.afterFingerprint, SHA256);
  equal(failures, `${label}.desiredFingerprint`, value.desiredFingerprint, value.afterFingerprint);
  pattern(failures, `${label}.checkedAt`, value.checkedAt, INSTANT);
  if (!Number.isSafeInteger(value.organizationCount) || value.organizationCount < 0) failures.push(`${label}.organizationCount-invalid`);
  const operation = object(value.operation, `${label}.operation`, failures);
  if (operation) exactKeys(operation, ["idempotencyKeyDigest", "operationKeyDigest", "requestFingerprintDigest"], `${label}.operation`, failures);
  pattern(failures, `${label}.operation.idempotencyKeyDigest`, value.operation?.idempotencyKeyDigest, SHA256);
  pattern(failures, `${label}.operation.operationKeyDigest`, value.operation?.operationKeyDigest, SHA256);
  pattern(failures, `${label}.operation.requestFingerprintDigest`, value.operation?.requestFingerprintDigest, SHA256);
  return value;
}

function validateRestorePair(apply: Record<string, any> | null, restore: Record<string, any> | null, failures: string[]) {
  if (!apply || !restore) return;
  equal(failures, "restore.targetFingerprint", restore.targetFingerprint, apply.targetFingerprint);
  equal(failures, "restore.beforeFingerprint", restore.beforeFingerprint, apply.afterFingerprint);
  equal(failures, "restore.afterFingerprint", restore.afterFingerprint, apply.beforeFingerprint);
  if (typeof apply.checkedAt === "string" && typeof restore.checkedAt === "string" && restore.checkedAt < apply.checkedAt) {
    failures.push("restore.checkedAt-before-apply");
  }
  if (restore.operation?.operationKeyDigest === apply.operation?.operationKeyDigest) failures.push("restore-operation-key-reused");
  if (restore.operation?.idempotencyKeyDigest === apply.operation?.idempotencyKeyDigest) failures.push("restore-idempotency-key-reused");
}

function validateFinalReconciliationChronology(
  reconciliation: Record<string, any> | null,
  restore: Record<string, any> | null,
  failures: string[]
) {
  if (!reconciliation || !restore) return;
  if (
    typeof restore.checkedAt === "string" &&
    INSTANT.test(restore.checkedAt) &&
    typeof reconciliation.windowStartedAt === "string" &&
    INSTANT.test(reconciliation.windowStartedAt) &&
    reconciliation.windowStartedAt < restore.checkedAt
  ) {
    failures.push("reconciliation-window-started-before-native-restore");
  }
}

function validateDefaultOff(
  value: Record<string, any> | null,
  revision: unknown,
  reconciliation: Record<string, any> | null,
  failures: string[]
) {
  if (!value) return;
  exactKeys(value, ["checkedAt", "contract", "failures", "passed", "results"], "defaultOff", failures);
  equal(failures, "defaultOff.contract", value.contract, ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT);
  pattern(failures, "defaultOff.checkedAt", value.checkedAt, INSTANT);
  equal(failures, "defaultOff.passed", value.passed, true);
  arrayEmpty(failures, "defaultOff.failures", value.failures);
  if (
    reconciliation &&
    typeof reconciliation.attestedAt === "string" &&
    INSTANT.test(reconciliation.attestedAt) &&
    typeof value.checkedAt === "string" &&
    INSTANT.test(value.checkedAt) &&
    value.checkedAt < reconciliation.attestedAt
  ) {
    failures.push("default-off-checked-before-final-reconciliation");
  }
  if (!Array.isArray(value.results) || value.results.length !== 1) {
    failures.push("defaultOff.results-must-contain-exactly-xrteeth-develop");
    return;
  }
  const result = value.results[0];
  const resultRecord = object(result, "defaultOff.result", failures);
  if (resultRecord) exactKeys(resultRecord, ["failures", "posture", "revision", "status", "url"], "defaultOff.result", failures);
  equal(failures, "defaultOff.url", result?.url, DEVELOP_HEALTH_URL);
  equal(failures, "defaultOff.status", result?.status, 200);
  equal(failures, "defaultOff.revision", result?.revision, revision);
  arrayEmpty(failures, "defaultOff.result.failures", result?.failures);
  const posture = result?.posture;
  const expected: Record<string, unknown> = {
    mode: "disabled", routeIntegrationEnabled: false, dualWriteExecutionEnabled: false,
    identityNativeExecutionEnabled: false, candidateMaterializationEnabled: false,
    candidateMaterializationTargetConfigured: false, candidateBatchMaterializationEnabled: false,
    candidateBatchMaterializationEnvironment: "disabled", recoveryDrillEnabled: false,
    recoveryDrillTargetConfigured: false, rolloutMode: "off", rolloutAllowlistCount: 0,
    rolloutPercentage: 0, sourceOfTruth: "legacy", identityNativeSupported: false
  };
  const postureRecord = object(posture, "defaultOff.posture", failures);
  if (postureRecord) exactKeys(postureRecord, Object.keys(expected), "defaultOff.posture", failures);
  for (const [name, expectedValue] of Object.entries(expected)) equal(failures, `defaultOff.posture.${name}`, posture?.[name], expectedValue);
}

function validateRegression(value: Record<string, any> | null, revision: unknown, failures: string[]) {
  if (!value) return null;
  exactKeys(value, [
    "buildRevision", "contract", "environment", "failedTests", "passedTests", "requiredTestFiles",
    "skippedTests", "success", "totalTests"
  ], "regression", failures);
  equal(failures, "regression.contract", value.contract, ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT);
  equal(failures, "regression.environment", value.environment, "xrteeth-develop");
  equal(failures, "regression.buildRevision", value.buildRevision, revision);
  equal(failures, "regression.success", value.success, true);
  equal(failures, "regression.failedTests", value.failedTests, 0);
  if (!Number.isSafeInteger(value.passedTests) || value.passedTests < 900) failures.push("regression.passedTests-below-900");
  if (!Number.isSafeInteger(value.skippedTests) || value.skippedTests < 0) failures.push("regression.skippedTests-invalid");
  equal(failures, "regression.totalTests", value.totalTests, value.passedTests + value.failedTests + value.skippedTests);
  exactStringArray(failures, "regression.requiredTestFiles", value.requiredTestFiles, [...REQUIRED_TEST_FILES]);
  return { passedTests: value.passedTests, failedTests: 0, skippedTests: value.skippedTests, requiredTestFiles: [...REQUIRED_TEST_FILES] };
}

function validateGovernance(value: unknown, failures: string[], now: Date) {
  const record = object(value, "manifest.governance", failures);
  if (!record) return;
  exactKeys(record, ["compatibilityRoutes", "monitoring", "reviewDate", "rollbackRoutes", "rollbackWindowHours"], "manifest.governance", failures);
  exactStringArray(failures, "governance.compatibilityRoutes", record.compatibilityRoutes, [
    "/v1/plugin-user/update-user", "/internal/iam/organization-write/subjects/:legacyUserId/candidate"
  ]);
  exactStringArray(failures, "governance.rollbackRoutes", record.rollbackRoutes, [
    "identity-native-membership-replace-to-reviewed-before-snapshot", "configuration-default-off"
  ]);
  exactStringArray(failures, "governance.monitoring", record.monitoring, [
    "health", "readiness", "operation-ledger", "candidate-snapshot", "full-reconciliation"
  ]);
  if (!Number.isSafeInteger(record.rollbackWindowHours) || record.rollbackWindowHours < 1 || record.rollbackWindowHours > 168) failures.push("governance.rollbackWindowHours-invalid");
  pattern(failures, "governance.reviewDate", record.reviewDate, DATE);
  if (typeof record.reviewDate === "string" && DATE.test(record.reviewDate) && record.reviewDate < now.toISOString().slice(0, 10)) failures.push("governance.reviewDate-in-past");
}

function validateSafety(value: unknown, failures: string[]) {
  const record = object(value, "manifest.safety", failures);
  if (!record) return;
  const expected = {
    developComplete: true, productionReady: false, productionPromotionAllowed: false,
    mainUntouched: true, publishUntouched: true, productionUntouched: true, tmrppUntouched: true,
    legacyCleanupAuthorized: false, legacyDataDeleted: false
  };
  exactKeys(record, Object.keys(expected), "manifest.safety", failures);
  for (const [name, expectedValue] of Object.entries(expected)) equal(failures, `manifest.safety.${name}`, record[name], expectedValue);
}

function evidenceRef(value: unknown, label: string, failures: string[]): EvidenceRef | null {
  const record = object(value, label, failures);
  if (!record) return null;
  exactKeys(record, ["path", "sha256"], label, failures);
  if (typeof record.path !== "string" || !record.path || isAbsolute(record.path) || normalize(record.path).split(sep).includes("..")) failures.push(`${label}.path-invalid`);
  pattern(failures, `${label}.sha256`, record.sha256, SHA256);
  return typeof record.path === "string" && typeof record.sha256 === "string" ? { path: record.path, sha256: record.sha256 } : null;
}

function resolveEvidencePath(root: string, candidate: string): string {
  const path = resolve(root, candidate);
  const rel = relative(root, path);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new Error("invalid evidence path");
  return path;
}

async function readStrictFile(path: string): Promise<Buffer> {
  if (typeof fsConstants.O_NOFOLLOW !== "number" || typeof fsConstants.O_NONBLOCK !== "number" || typeof process.getuid !== "function") throw new Error("unsupported platform");
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.uid !== process.getuid() ||
    (before.mode & 0o077) !== 0 || before.size < 2 || before.size > MAX_FILE_BYTES) throw new Error("invalid file");
  const canonical = await realpath(path);
  if (canonical !== path) throw new Error("noncanonical path");
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size || opened.uid !== before.uid || opened.nlink !== 1) throw new Error("file race");
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (read.bytesRead <= 0) throw new Error("short read");
      offset += read.bytesRead;
    }
    const probe = Buffer.alloc(1);
    if ((await handle.read(probe, 0, 1, offset)).bytesRead !== 0) throw new Error("file grew");
    const after = await handle.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) throw new Error("file changed");
    return bytes;
  } finally { await handle.close(); }
}

function parseObject(bytes: Buffer, label: string, failures: string[]): Record<string, any> | null {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = JSON.parse(text) as unknown;
    if (text !== `${JSON.stringify(value)}\n`) {
      failures.push(`${label}-canonical-json-invalid`);
      return null;
    }
    return object(value, label, failures);
  } catch { failures.push(`${label}-json-invalid`); return null; }
}

function object(value: unknown, label: string, failures: string[]): Record<string, any> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) { failures.push(`${label}-object-invalid`); return null; }
  return value as Record<string, any>;
}

function exactKeys(value: Record<string, any>, keys: readonly string[], label: string, failures: string[]) {
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) failures.push(`${label}-keys-invalid`);
}

function exactStringArray(failures: string[], label: string, actual: unknown, expected: string[]) {
  if (!Array.isArray(actual) || JSON.stringify(actual) !== JSON.stringify(expected)) failures.push(`${label}-invalid`);
}

function pair(failures: string[], label: string, value: any, count: number) {
  equal(failures, `${label}.verified`, value?.verified, count); equal(failures, `${label}.required`, value?.required, count);
}

function arrayEmpty(failures: string[], label: string, value: unknown) {
  if (!Array.isArray(value) || value.length !== 0) failures.push(`${label}-not-empty`);
}

function pattern(failures: string[], label: string, value: unknown, regex: RegExp) {
  if (typeof value !== "string" || !regex.test(value)) failures.push(`${label}-invalid`);
}

function equal(failures: string[], label: string, actual: unknown, expected: unknown) {
  if (actual !== expected) failures.push(`${label}-mismatch`);
}

function sha256(bytes: Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }

function report(now: Date, failures: string[], summary: Record<string, unknown> | null): OrganizationWorkPackage4DevelopCompletionGateReport {
  return { passed: failures.length === 0, status: failures.length === 0 ? "completed" : "blocked", checkedAt: now.toISOString(), failures: [...new Set(failures)].sort(), summary };
}

async function main() {
  const arg = process.argv.slice(2).find((value) => value.startsWith("--manifest="));
  if (!arg || process.argv.slice(2).length !== 1) throw new Error("Usage: --manifest=<absolute-path>");
  const path = arg.slice("--manifest=".length);
  if (!isAbsolute(path)) throw new Error("manifest must be an absolute path");
  const output = await validateOrganizationWorkPackage4DevelopCompletion(path);
  process.stdout.write(`${JSON.stringify(output)}\n`);
  if (!output.passed) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
