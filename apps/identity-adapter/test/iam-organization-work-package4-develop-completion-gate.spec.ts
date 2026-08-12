import { createHash } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/iam-organization-reconciliation-develop-deployment-topology.js", () => ({
  bindOrganizationReconciliationDevelopDeploymentEvidenceToCompiledTopology: (candidate: unknown) =>
    Object.freeze({ topology: Object.freeze({ profileId: "test" }), deploymentEvidence: candidate,
      physicalIndependenceVerified: false as const, productionPromotionAllowed: false as const })
}));

import {
  createOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCertificate,
  serializeOrganizationReconciliationDevelopRuntimeCloseout
} from "../src/iam-organization-reconciliation-develop-runtime-verification-certificate.js";
import {
  createOrganizationReconciliationDevelopRuntimeCertificateTestFixture
} from "./iam-organization-reconciliation-develop-runtime-verification-certificate.test-fixture.js";
import {
  ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_MANIFEST_CONTRACT,
  ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT,
  validateOrganizationWorkPackage4DevelopCompletion
} from "../../../scripts/iam-organization-work-package4-develop-completion-gate.js";
import { ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT } from "../../../scripts/iam-organization-identity-native-window-gate.js";
import { ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT } from "../../../scripts/iam-organization-write-public-gate.js";

const roots: string[] = [];
const REQUIRED_TEST_FILES = [
  "iam-organization-identity-native.spec.ts",
  "iam-organization-identity-native-window-gate.spec.ts",
  "plugin-user-primary-read-organization-native.spec.ts",
  "iam-organization-reconciliation-develop-full-pipeline.spec.ts",
  "iam-organization-reconciliation-develop-plugin-campus-surfaces.spec.ts",
  "identity-adapter.spec.ts"
] as const;

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Work Package 4 Develop completion gate", () => {
  it("completes only when 7.2, native forward/restore, default-off, regression, and governance agree", async () => {
    const fixture = await createFixture();
    await expect(validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now))
      .resolves.toMatchObject({
        passed: true,
        status: "completed",
        failures: [],
        summary: {
          task: "11.1-11.5",
          status: "develop-complete-production-pending-approval",
          ownerDecision: "identity-native",
          buildRevision: fixture.revision,
          reconciliation: { datasets: "21/21", surfaces: "8/8", attestations: "1/1", physicalProbePasses: "6/6" },
          nativeWindow: {
            beforeFingerprint: "1".repeat(64),
            forwardFingerprint: "2".repeat(64),
            restoredFingerprint: "1".repeat(64)
          },
          safety: {
            developComplete: true,
            productionReady: false,
            productionPromotionAllowed: false,
            legacyCleanupAuthorized: false,
            legacyDataDeleted: false
          }
        }
      });
  });

  it("rejects an evidence byte change even when manifest fields remain plausible", async () => {
    const fixture = await createFixture();
    const applyPath = join(fixture.root, "native-apply.json");
    const apply = JSON.parse(await BunFile(applyPath)) as Record<string, unknown>;
    apply.organizationCount = 99;
    await writeJson(applyPath, apply);

    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("evidence.nativeApply.sha256-mismatch");
  });

  it("rejects a restore that does not invert the reviewed forward window", async () => {
    const fixture = await createFixture({ restoreAfter: "3".repeat(64) });
    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("restore.afterFingerprint-mismatch");
  });

  it("rejects reconciliation collected before the final Identity-native restore", async () => {
    const fixture = await createFixture({ restoreCheckedAt: "2026-08-09T00:02:00.000Z" });
    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("reconciliation-window-started-before-native-restore");
  });

  it("rejects default-off evidence collected before the final reconciliation", async () => {
    const fixture = await createFixture({ defaultOffCheckedAt: "2026-08-09T00:04:00.000Z" });
    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("default-off-checked-before-final-reconciliation");
  });

  it("rejects Production promotion, Legacy cleanup, missing required regression, and stale review date", async () => {
    const fixture = await createFixture({
      safety: { productionPromotionAllowed: true, legacyCleanupAuthorized: true },
      requiredTests: REQUIRED_TEST_FILES.slice(0, -1),
      reviewDate: "2026-08-11"
    });
    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toEqual(expect.arrayContaining([
      "manifest.safety.productionPromotionAllowed-mismatch",
      "manifest.safety.legacyCleanupAuthorized-mismatch",
      "regression.requiredTestFiles-invalid",
      "governance.reviewDate-in-past"
    ]));
  });

  it("rejects evidence path reuse and symlinks", async () => {
    const reused = await createFixture({ reuseRestorePath: true });
    await expect(validateOrganizationWorkPackage4DevelopCompletion(reused.manifestPath, reused.now))
      .resolves.toMatchObject({ passed: false, failures: expect.arrayContaining(["evidence-path-reused:nativeRestore"]) });

    const linked = await createFixture();
    const target = join(linked.root, "native-apply.json");
    const link = join(linked.root, "native-apply-link.json");
    await symlink(target, link);
    const manifest = JSON.parse(await BunFile(linked.manifestPath)) as any;
    manifest.evidence.nativeApply.path = "native-apply-link.json";
    await writeJson(linked.manifestPath, manifest);
    const report = await validateOrganizationWorkPackage4DevelopCompletion(linked.manifestPath, linked.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("evidence-file-invalid:nativeApply");
  });

  it("rejects non-canonical JSON and duplicate keys before accepting evidence", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.manifestPath, `{\"contract\":\"x\",\"contract\":\"y\"}\n`, { mode: 0o600 });
    const report = await validateOrganizationWorkPackage4DevelopCompletion(fixture.manifestPath, fixture.now);
    expect(report.passed).toBe(false);
    expect(report.failures).toContain("manifest-canonical-json-invalid");
  });
});

async function createFixture(input: {
  restoreAfter?: string;
  safety?: Record<string, boolean>;
  requiredTests?: readonly string[];
  reviewDate?: string;
  reuseRestorePath?: boolean;
  restoreCheckedAt?: string;
  defaultOffCheckedAt?: string;
} = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "iam-wp4-completion-")));
  roots.push(root);
  await chmod(root, 0o700);
  const runtime = createOrganizationReconciliationDevelopRuntimeCertificateTestFixture();
  const artifacts = createOrganizationReconciliationDevelopRuntimeCertificate(runtime.input);
  const revision = artifacts.certificate.buildRevision;
  const task72Certificate = JSON.parse(serializeOrganizationReconciliationDevelopRuntimeCertificate(artifacts.certificate));
  const task72 = JSON.parse(serializeOrganizationReconciliationDevelopRuntimeCloseout(artifacts.closeout, artifacts.certificate));
  const nativeApply = windowOutput(revision, "1".repeat(64), "2".repeat(64), "a");
  const nativeRestore = { ...windowOutput(revision, "2".repeat(64), input.restoreAfter ?? "1".repeat(64), "b"),
    checkedAt: input.restoreCheckedAt ?? "2026-08-09T00:00:20.000Z" };
  const defaultOff = {
    contract: ORGANIZATION_WRITE_PUBLIC_GATE_CONTRACT,
    checkedAt: input.defaultOffCheckedAt ?? "2026-08-09T00:08:00.000Z",
    passed: true,
    results: [{
      url: "https://identity.d.xrteeth.com/health",
      status: 200,
      revision,
      posture: {
        mode: "disabled", routeIntegrationEnabled: false, dualWriteExecutionEnabled: false,
        identityNativeExecutionEnabled: false, candidateMaterializationEnabled: false,
        candidateMaterializationTargetConfigured: false, candidateBatchMaterializationEnabled: false,
        candidateBatchMaterializationEnvironment: "disabled", recoveryDrillEnabled: false,
        recoveryDrillTargetConfigured: false, rolloutMode: "off", rolloutAllowlistCount: 0,
        rolloutPercentage: 0, sourceOfTruth: "legacy", identityNativeSupported: false
      },
      failures: []
    }],
    failures: []
  };
  const requiredTests = input.requiredTests ?? REQUIRED_TEST_FILES;
  const regression = {
    contract: ORGANIZATION_WORK_PACKAGE4_DEVELOP_REGRESSION_SUMMARY_CONTRACT,
    environment: "xrteeth-develop",
    buildRevision: revision,
    success: true,
    passedTests: 926,
    failedTests: 0,
    skippedTests: 5,
    totalTests: 931,
    requiredTestFiles: [...requiredTests]
  };
  const files = { task72, task72Certificate, nativeApply, nativeRestore, defaultOff, regression };
  const refs: Record<string, { path: string; sha256: string }> = {};
  for (const [name, value] of Object.entries(files)) {
    const file = fileName(name);
    const path = join(root, file);
    await writeJson(path, value);
    refs[name] = { path: file, sha256: sha256(Buffer.from(`${JSON.stringify(value)}\n`)) };
  }
  if (input.reuseRestorePath) refs.nativeRestore = { ...refs.nativeApply };
  const safety = {
    developComplete: true,
    productionReady: false,
    productionPromotionAllowed: false,
    mainUntouched: true,
    publishUntouched: true,
    productionUntouched: true,
    tmrppUntouched: true,
    legacyCleanupAuthorized: false,
    legacyDataDeleted: false,
    ...input.safety
  };
  const manifest = {
    contract: ORGANIZATION_WORK_PACKAGE4_DEVELOP_COMPLETION_MANIFEST_CONTRACT,
    task: "11.1-11.5",
    environment: "xrteeth-develop",
    ownerDecision: "identity-native",
    buildRevision: revision,
    evidence: {
      task72: refs.task72,
      task72Certificate: refs.task72Certificate,
      nativeApply: refs.nativeApply,
      nativeRestore: refs.nativeRestore,
      defaultOff: refs.defaultOff,
      regression: refs.regression
    },
    governance: {
      compatibilityRoutes: [
        "/v1/plugin-user/update-user", "/internal/iam/organization-write/subjects/:legacyUserId/candidate"
      ],
      rollbackRoutes: [
        "identity-native-membership-replace-to-reviewed-before-snapshot", "configuration-default-off"
      ],
      monitoring: ["health", "readiness", "operation-ledger", "candidate-snapshot", "full-reconciliation"],
      rollbackWindowHours: 24,
      reviewDate: input.reviewDate ?? "2026-09-12"
    },
    safety
  };
  const manifestPath = join(root, "manifest.json");
  await writeJson(manifestPath, manifest);
  return { root, manifestPath, revision, now: new Date("2026-08-12T12:00:00.000Z") };
}

function windowOutput(revision: string, before: string, after: string, key: string) {
  return {
    contract: ORGANIZATION_IDENTITY_NATIVE_WINDOW_GATE_CONTRACT,
    environment: "xrteeth-develop",
    scope: "membership-replace",
    mode: "apply",
    checkedAt: "2026-08-09T00:00:10.000Z",
    revision,
    targetFingerprint: "1".repeat(16),
    organizationCount: 1,
    organizationSetSha256: `${key === "a" ? "4" : "5"}`.repeat(64),
    passed: true,
    applyAttempted: true,
    outcomeUnknown: false,
    beforeFingerprint: before,
    afterFingerprint: after,
    desiredFingerprint: after,
    operation: {
      idempotencyKeyDigest: key.repeat(64),
      operationKeyDigest: (key === "a" ? "c" : "d").repeat(64),
      requestFingerprintDigest: (key === "a" ? "e" : "f").repeat(64)
    },
    failures: []
  };
}

function fileName(name: string): string {
  return name.replace(/[A-Z]/g, (value) => `-${value.toLowerCase()}`) + ".json";
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function BunFile(path: string): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  return readFile(path, "utf8");
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
