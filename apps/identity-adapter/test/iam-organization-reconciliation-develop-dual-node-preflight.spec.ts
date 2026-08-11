import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createOrganizationReconciliationDevelopDualNodePreflightReport,
  ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_BLOCKERS,
  ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_READY
} from "../src/iam-organization-reconciliation-develop-dual-node-preflight.js";
import type {
  OrganizationReconciliationDevelopSourcePreflightReport
} from "../src/iam-organization-reconciliation-develop-source-preflight.js";
import {
  readCanonicalDevelopPreflightReportFile,
  runOrganizationReconciliationDevelopDualNodePreflightCli
} from "../../../scripts/iam-organization-reconciliation-develop-dual-node-preflight.js";

const BUILD = "a".repeat(40);
const SHA = "b".repeat(64);
const CHECK_IDS = [
  "all-components-probed",
  "all-component-database-bindings-exact",
  "all-component-grants-read-only-and-table-bounded",
  "all-21-datasets-probed",
  "legacy-reconciliation-capability-catalog-present",
  "legacy-reconciliation-scope-rule-free",
  "identity-legacy-subjects-complete",
  "identity-subjects-unique",
  "identity-organizations-complete",
  "identity-legacy-membership-snapshots-complete",
  "identity-membership-counts-complete",
  "identity-policy-version-pinned",
  "identity-policy-version-decoder-probed",
  "identity-policy-role-count",
  "identity-policy-permission-count",
  "identity-policy-relation-count",
  "plugin-scopes-valid",
  "plugin-empty-organization-name-absent",
  "build-revision-pinned"
] as const;

describe("xrteeth Develop dual-node source-preflight alignment", () => {
  it("aligns two complete sanitized reports without claiming collector or production trust", () => {
    const result = createOrganizationReconciliationDevelopDualNodePreflightReport([
      { nodeId: "develop-node-b", report: sourceReport("2026-08-10T08:00:02.000Z") },
      { nodeId: "develop-node-a", report: sourceReport("2026-08-10T08:00:00.000Z") }
    ], options());

    expect(ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_READY).toBe(false);
    expect(result).toMatchObject({
      contract: "iam-organization-reconciliation-xrteeth-develop-dual-node-source-preflight/v1",
      environment: "xrteeth-develop",
      mode: "read-only",
      assuranceScope: "structural-dual-node-source-preflight-only",
      nodeIds: ["develop-node-a", "develop-node-b"],
      windowStartedAt: "2026-08-10T08:00:00.000Z",
      windowEndedAt: "2026-08-10T08:00:02.000Z",
      componentCount: 3,
      datasetProbeCount: 21,
      sourcePreflightAligned: true,
      collectorSignaturesVerified: false,
      productionReady: false,
      blockers: ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_BLOCKERS
    });
    expect(result.alignedSourceSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.reportSetSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.nodeIds)).toBe(true);
  });

  it("is order-independent for node labels while binding each timestamped report set", () => {
    const first = createOrganizationReconciliationDevelopDualNodePreflightReport([
      { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:02.000Z") },
      { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") }
    ], options());
    const second = createOrganizationReconciliationDevelopDualNodePreflightReport([
      { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") },
      { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:02.000Z") }
    ], options());
    expect(first).toEqual(second);
  });

  it("rejects source, schema, grant, count, catalog, policy, and build A/B splices", () => {
    const mutations: Array<(report: MutableReport) => void> = [
      (report) => { report.buildRevision = "c".repeat(40); },
      (report) => { report.sourceCatalogSha256 = "c".repeat(64); },
      (report) => { report.statementCatalogSha256 = "e".repeat(64); },
      (report) => { report.iamPolicyChecksum = "e".repeat(64); },
      (report) => { report.components[0]!.sourceIdentitySha256 = "c".repeat(64); },
      (report) => { report.components[0]!.grantScopeSha256 = "c".repeat(64); },
      (report) => { report.components[0]!.physicalSchemaSha256 = "c".repeat(64); },
      (report) => { report.components[0]!.aggregateCounts.legacy_subject_count = 3; },
      (report) => { report.subjectUniverseComparison.identitySelectedSubjectCount = 3; },
      (report) => { report.membershipSnapshotComparison.snapshotSubjectCount = 3; }
    ];
    for (const mutate of mutations) {
      const changed = mutableReport();
      mutate(changed);
      expect(() => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") },
        { nodeId: "node-b", report: changed as OrganizationReconciliationDevelopSourcePreflightReport }
      ], options())).toThrow("invalid or misaligned");
    }
  });

  it("requires the exact component, aggregate, and check universes", () => {
    const duplicateComponent = mutableReport();
    duplicateComponent.components[1]!.componentId = "legacy-main";
    const missingAggregate = mutableReport();
    delete missingAggregate.components[0]!.aggregateCounts.legacy_subject_count;
    const extraAggregate = mutableReport();
    extraAggregate.components[2]!.aggregateCounts.unreviewed = 0;
    const duplicateCheck = mutableReport();
    duplicateCheck.checks[1]!.checkId = duplicateCheck.checks[0]!.checkId;
    for (const candidate of [duplicateComponent, missingAggregate, extraAggregate, duplicateCheck]) {
      expect(() => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: candidate as OrganizationReconciliationDevelopSourcePreflightReport },
        { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:00.000Z") }
      ], options())).toThrow("invalid or misaligned");
    }
  });

  it("rejects failed, stale, future, over-skewed, or duplicate-node reports", () => {
    const failed = mutableReport();
    failed.passed = false;
    failed.failures = ["all-components-probed"];
    failed.checks[0]!.passed = false;
    const cases = [
      () => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: failed as OrganizationReconciliationDevelopSourcePreflightReport },
        { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:00.000Z") }
      ], options()),
      () => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: sourceReport("2026-08-10T07:00:00.000Z") },
        { nodeId: "node-b", report: sourceReport("2026-08-10T07:00:01.000Z") }
      ], options()),
      () => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: sourceReport("2026-08-10T08:10:01.000Z") },
        { nodeId: "node-b", report: sourceReport("2026-08-10T08:10:02.000Z") }
      ], options()),
      () => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") },
        { nodeId: "node-b", report: sourceReport("2026-08-10T08:06:00.000Z") }
      ], options()),
      () => createOrganizationReconciliationDevelopDualNodePreflightReport([
        { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") },
        { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:01.000Z") }
      ], options())
    ];
    for (const candidate of cases) expect(candidate).toThrow("invalid or misaligned");
  });

  it("captures own data descriptors without invoking getters or accepting structural clones with hidden data", () => {
    let getterCalls = 0;
    const accessor = Object.create(Object.prototype, {
      nodeId: { enumerable: true, get: () => { getterCalls += 1; return "node-a"; } },
      report: { enumerable: true, value: sourceReport("2026-08-10T08:00:00.000Z") }
    });
    expect(() => createOrganizationReconciliationDevelopDualNodePreflightReport([
      accessor,
      { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:01.000Z") }
    ] as never, options())).toThrow("invalid or misaligned");
    expect(getterCalls).toBe(0);

    const hidden = { nodeId: "node-a", report: sourceReport("2026-08-10T08:00:00.000Z") };
    Object.defineProperty(hidden.report, "hidden", { enumerable: false, value: true });
    expect(() => createOrganizationReconciliationDevelopDualNodePreflightReport([
      hidden,
      { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:01.000Z") }
    ], options())).toThrow("invalid or misaligned");

    let proxyTraps = 0;
    const proxied = new Proxy(sourceReport("2026-08-10T08:00:00.000Z"), {
      ownKeys: (target) => { proxyTraps += 1; return Reflect.ownKeys(target); }
    });
    expect(() => createOrganizationReconciliationDevelopDualNodePreflightReport([
      { nodeId: "node-a", report: proxied },
      { nodeId: "node-b", report: sourceReport("2026-08-10T08:00:01.000Z") }
    ], options())).toThrow("invalid or misaligned");
    expect(proxyTraps).toBe(0);
  });

  it("exposes a strict Develop-only CLI without reading files on invalid arguments", async () => {
    let reads = 0;
    const stdout: string[] = [];
    const stderr: string[] = [];
    const io = {
      readReportFile: async () => { reads += 1; return sourceReport("2026-08-10T08:00:00.000Z"); },
      now: () => new Date("2026-08-10T08:10:00.000Z"),
      stdout: (text: string) => stdout.push(text),
      stderr: (text: string) => stderr.push(text)
    };
    expect(await runOrganizationReconciliationDevelopDualNodePreflightCli(["--help"], io)).toBe(0);
    expect(stdout.join("")).toContain("structural alignment");
    expect(stderr).toEqual([]);
    stdout.length = 0;
    expect(await runOrganizationReconciliationDevelopDualNodePreflightCli([
      "--environment=production",
      `--expected-build-revision=${BUILD}`,
      "--node-a-id=node-a",
      "--node-a-report=a.json",
      "--node-b-id=node-b",
      "--node-b-report=b.json"
    ], io)).toBe(2);
    expect(reads).toBe(0);
    expect(stdout).toEqual([]);
    expect(stderr.join("")).not.toContain("production");
  });

  it("runs the CLI on two sanitized reports and emits only the structural summary", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const paths: string[] = [];
    const reports = new Map<string, unknown>([
      ["a.json", sourceReport("2026-08-10T08:00:00.000Z")],
      ["b.json", sourceReport("2026-08-10T08:00:01.000Z")]
    ]);
    expect(await runOrganizationReconciliationDevelopDualNodePreflightCli([
      "--node-b-report=b.json",
      "--environment=xrteeth-develop",
      "--node-a-id=node-a",
      `--expected-build-revision=${BUILD}`,
      "--node-b-id=node-b",
      "--node-a-report=a.json"
    ], {
      readReportFile: async (path) => { paths.push(path); return reports.get(path); },
      now: () => new Date("2026-08-10T08:10:00.000Z"),
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    })).toBe(0);
    expect(paths.sort()).toEqual(["a.json", "b.json"]);
    expect(stderr).toEqual([]);
    expect(JSON.parse(stdout.join(""))).toMatchObject({
      sourcePreflightAligned: true,
      collectorSignaturesVerified: false,
      productionReady: false
    });
    expect(stdout.join("")).not.toContain("aggregateCounts");
  });

  it("returns one fixed CLI error without echoing paths or mismatched report content", async () => {
    const changed = mutableReport();
    changed.components[0]!.physicalSchemaSha256 = "e".repeat(64);
    const stdout: string[] = [];
    const stderr: string[] = [];
    expect(await runOrganizationReconciliationDevelopDualNodePreflightCli([
      "--environment=xrteeth-develop",
      `--expected-build-revision=${BUILD}`,
      "--node-a-id=node-a",
      "--node-a-report=secret-a.json",
      "--node-b-id=node-b",
      "--node-b-report=secret-b.json"
    ], {
      readReportFile: async (path) => path.includes("a")
        ? sourceReport("2026-08-10T08:00:00.000Z")
        : changed,
      now: () => new Date("2026-08-10T08:10:00.000Z"),
      stdout: (text) => stdout.push(text),
      stderr: (text) => stderr.push(text)
    })).toBe(2);
    expect(stdout).toEqual([]);
    expect(stderr.join("")).toBe("The dual-node Develop source-preflight evidence is invalid or misaligned.\n");
    expect(stderr.join("")).not.toContain("secret-a");
    expect(stderr.join("")).not.toContain("physicalSchema");
  });

  it("reads only exact canonical, ordinary, unlinked local report files", async () => {
    const directory = await mkdtemp(join(tmpdir(), "identity-dual-node-preflight-"));
    try {
      const reportPath = join(directory, "report.json");
      const report = sourceReport("2026-08-10T08:00:00.000Z");
      await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      expect(await readCanonicalDevelopPreflightReportFile(reportPath)).toEqual(report);

      const nonCanonicalPath = join(directory, "non-canonical.json");
      await writeFile(nonCanonicalPath, `${JSON.stringify(report)}\n`, { encoding: "utf8", mode: 0o600 });
      await expect(readCanonicalDevelopPreflightReportFile(nonCanonicalPath)).rejects.toThrow("invalid-local-report");

      const duplicateKeyPath = join(directory, "duplicate-key.json");
      const canonical = JSON.stringify(report, null, 2);
      await writeFile(duplicateKeyPath, canonical.replace("{", `{\n  \"passed\": true,` ) + "\n", {
        encoding: "utf8",
        mode: 0o600
      });
      await expect(readCanonicalDevelopPreflightReportFile(duplicateKeyPath)).rejects.toThrow("invalid-local-report");

      const linkPath = join(directory, "report-link.json");
      await symlink(reportPath, linkPath);
      await expect(readCanonicalDevelopPreflightReportFile(linkPath)).rejects.toThrow();
      await expect(readCanonicalDevelopPreflightReportFile("https://example.invalid/report.json"))
        .rejects.toThrow("invalid-local-report");
      await expect(readCanonicalDevelopPreflightReportFile("-")).rejects.toThrow("invalid-local-report");

      const fifoPath = join(directory, "blocked.fifo");
      const mkfifo = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
      expect(mkfifo.status).toBe(0);
      await expect(Promise.race([
        readCanonicalDevelopPreflightReportFile(fifoPath),
        new Promise((_, reject) => setTimeout(() => reject(new Error("fifo-open-blocked")), 1_000))
      ])).rejects.toThrow("invalid-local-report");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

function options() {
  return {
    expectedBuildRevision: BUILD,
    now: new Date("2026-08-10T08:10:00.000Z"),
    maxEvidenceAgeSeconds: 900,
    maxNodeSkewSeconds: 300
  };
}

function sourceReport(checkedAt: string): OrganizationReconciliationDevelopSourcePreflightReport {
  const report = mutableReport();
  report.checkedAt = checkedAt;
  return report as OrganizationReconciliationDevelopSourcePreflightReport;
}

type MutableReport = ReturnType<typeof mutableReport>;

function mutableReport() {
  return {
    contract: "iam-organization-reconciliation-xrteeth-develop-source-preflight/v4" as const,
    environment: "xrteeth-develop" as const,
    mode: "read-only" as const,
    checkedAt: "2026-08-10T08:00:00.000Z",
    buildRevision: BUILD,
    sourceCatalogSha256: SHA,
    statementCatalogSha256: "c".repeat(64),
    iamPolicyChecksum: "d".repeat(64),
    components: [
      component("legacy-main", 7, {
        legacy_active_subject_count: 2,
        legacy_membership_count: 2,
        legacy_named_rule_count: 0,
        legacy_organization_count: 1,
        legacy_rbac_assignment_count: 2,
        legacy_rbac_edge_count: 2,
        legacy_rbac_item_count: 11,
        legacy_role_assignment_count: 2,
        legacy_subject_count: 2
      }),
      component("identity", 13, {
        identity_iam_declared_permission_count: 11,
        identity_iam_declared_relation_count: 2,
        identity_iam_declared_role_count: 4,
        identity_iam_permission_count: 11,
        identity_iam_policy_version_count: 1,
        identity_iam_relation_count: 2,
        identity_iam_role_count: 4,
        identity_iam_subject_assignment_count: 2,
        identity_membership_candidate_count: 2,
        identity_membership_shadow_count: 2,
        identity_membership_snapshot_count: 2,
        identity_membership_snapshot_organization_sum: 2,
        identity_organization_candidate_count: 1,
        identity_organization_id_map_count: 1,
        identity_role_shadow_count: 2,
        identity_subject_collision_count: 0,
        identity_subject_count: 2
      }),
      component("plugin", 1, {
        plugin_count: 2,
        plugin_empty_organization_name_count: 0,
        plugin_enabled_count: 2,
        plugin_invalid_scope_count: 0
      })
    ],
    subjectUniverseComparison: {
      legacySubjectCount: 2,
      identitySelectedSubjectCount: 2,
      missingInIdentityCount: 0,
      extraInIdentityCount: 0
    },
    legacyRbacScope: {
      targetCount: 11,
      presentTargetCount: 11,
      namedRuleIntersectionCount: 0
    },
    membershipSnapshotComparison: {
      legacySubjectCount: 2,
      protectedLegacySubjectCount: 0,
      expectedSnapshotSubjectCount: 2,
      snapshotSubjectCount: 2,
      missingExpectedSnapshotCount: 0,
      unexpectedProtectedSnapshotCount: 0,
      extraSnapshotCount: 0
    },
    checks: CHECK_IDS.map((checkId) => ({ checkId, passed: true })),
    failures: [] as string[],
    passed: true,
    productionReady: false as const
  };
}

function component(
  componentId: "legacy-main" | "identity" | "plugin",
  datasetProbeCount: number,
  aggregateCounts: Record<string, number>
) {
  return {
    componentId,
    sourceIdentitySha256: `${componentId === "legacy-main" ? "1" : componentId === "identity" ? "2" : "3"}`.repeat(64),
    databaseBindingPassed: true,
    readOnlyGrantPassed: true,
    grantScopeSha256: `${componentId === "legacy-main" ? "4" : componentId === "identity" ? "5" : "6"}`.repeat(64),
    physicalSchemaSha256: `${componentId === "legacy-main" ? "7" : componentId === "identity" ? "8" : "9"}`.repeat(64),
    schemaShapePassed: true,
    requiredColumnCount: 4,
    observedColumnCount: 4,
    datasetProbeCount,
    nonEmptyDatasetProbeCount: datasetProbeCount,
    aggregateCounts
  };
}
