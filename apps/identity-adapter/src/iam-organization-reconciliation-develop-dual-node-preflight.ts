import { createHash } from "node:crypto";
import { isProxy } from "node:util/types";
import { z } from "zod";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_PREFLIGHT_CONTRACT,
  type OrganizationReconciliationDevelopSourcePreflightReport
} from "./iam-organization-reconciliation-develop-source-preflight.js";

export const ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_CONTRACT =
  "iam-organization-reconciliation-xrteeth-develop-dual-node-source-preflight/v1" as const;

export const ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_READY = false;

export const ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_BLOCKERS = Object.freeze([
  "collector-signatures-not-verified",
  "compiled-collector-build-pin-not-provisioned",
  "compiled-trust-profile-not-provisioned",
  "full-operation-evidence-not-collected",
  "production-readiness-remains-false"
] as const);

const SHA256 = /^[a-f0-9]{64}$/;
const BUILD_REVISION = /^[a-f0-9]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_COUNT = 10_000_000;
const EXPECTED_DATASET_PROBE_COUNTS = Object.freeze({
  "legacy-main": 7,
  identity: 13,
  plugin: 1
} as const);
const EXPECTED_AGGREGATE_KEYS = Object.freeze({
  "legacy-main": Object.freeze([
    "legacy_active_subject_count",
    "legacy_membership_count",
    "legacy_named_rule_count",
    "legacy_organization_count",
    "legacy_rbac_assignment_count",
    "legacy_rbac_edge_count",
    "legacy_rbac_item_count",
    "legacy_role_assignment_count",
    "legacy_subject_count"
  ]),
  identity: Object.freeze([
    "identity_iam_declared_permission_count",
    "identity_iam_declared_relation_count",
    "identity_iam_declared_role_count",
    "identity_iam_permission_count",
    "identity_iam_policy_version_count",
    "identity_iam_relation_count",
    "identity_iam_role_count",
    "identity_iam_subject_assignment_count",
    "identity_membership_candidate_count",
    "identity_membership_shadow_count",
    "identity_membership_snapshot_count",
    "identity_membership_snapshot_organization_sum",
    "identity_organization_candidate_count",
    "identity_organization_id_map_count",
    "identity_role_shadow_count",
    "identity_subject_collision_count",
    "identity_subject_count"
  ]),
  plugin: Object.freeze([
    "plugin_count",
    "plugin_empty_organization_name_count",
    "plugin_enabled_count",
    "plugin_invalid_scope_count"
  ])
} as const);
const EXPECTED_CHECK_IDS = Object.freeze([
  "all-21-datasets-probed",
  "all-component-database-bindings-exact",
  "all-component-grants-read-only-and-table-bounded",
  "all-components-probed",
  "build-revision-pinned",
  "identity-legacy-membership-snapshots-complete",
  "identity-legacy-subjects-complete",
  "identity-membership-counts-complete",
  "identity-organizations-complete",
  "identity-policy-permission-count",
  "identity-policy-relation-count",
  "identity-policy-role-count",
  "identity-policy-version-decoder-probed",
  "identity-policy-version-pinned",
  "identity-subjects-unique",
  "legacy-reconciliation-capability-catalog-present",
  "legacy-reconciliation-scope-rule-free",
  "plugin-empty-organization-name-absent",
  "plugin-scopes-valid"
]);

const canonicalTimestamp = z.string().refine((value) => {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
});
const safeCount = z.number().int().min(0).max(MAX_COUNT);
const aggregateCounts = z.record(z.string().min(1).max(128), safeCount);
const componentId = z.enum(["legacy-main", "identity", "plugin"]);
const componentSchema = z.object({
  componentId,
  sourceIdentitySha256: z.string().regex(SHA256),
  databaseBindingPassed: z.literal(true),
  readOnlyGrantPassed: z.literal(true),
  grantScopeSha256: z.string().regex(SHA256),
  physicalSchemaSha256: z.string().regex(SHA256),
  schemaShapePassed: z.literal(true),
  requiredColumnCount: safeCount,
  observedColumnCount: safeCount,
  datasetProbeCount: safeCount,
  nonEmptyDatasetProbeCount: safeCount,
  aggregateCounts
}).strict();
const countComparisonSchema = z.object({
  legacySubjectCount: safeCount,
  identitySelectedSubjectCount: safeCount,
  missingInIdentityCount: z.literal(0),
  extraInIdentityCount: safeCount
}).strict();
const rbacScopeSchema = z.object({
  targetCount: safeCount,
  presentTargetCount: safeCount,
  namedRuleIntersectionCount: z.literal(0)
}).strict();
const membershipSnapshotSchema = z.object({
  legacySubjectCount: safeCount,
  protectedLegacySubjectCount: safeCount,
  expectedSnapshotSubjectCount: safeCount,
  snapshotSubjectCount: safeCount,
  missingExpectedSnapshotCount: z.literal(0),
  unexpectedProtectedSnapshotCount: z.literal(0),
  extraSnapshotCount: z.literal(0)
}).strict();
const sourceReportSchema = z.object({
  contract: z.literal(ORGANIZATION_RECONCILIATION_DEVELOP_SOURCE_PREFLIGHT_CONTRACT),
  environment: z.literal("xrteeth-develop"),
  mode: z.literal("read-only"),
  checkedAt: canonicalTimestamp,
  buildRevision: z.string().regex(BUILD_REVISION),
  sourceCatalogSha256: z.string().regex(SHA256),
  statementCatalogSha256: z.string().regex(SHA256),
  iamPolicyChecksum: z.string().regex(SHA256),
  components: z.array(componentSchema).length(3),
  subjectUniverseComparison: countComparisonSchema,
  legacyRbacScope: rbacScopeSchema,
  membershipSnapshotComparison: membershipSnapshotSchema,
  checks: z.array(z.object({
    checkId: z.string().min(1).max(128),
    passed: z.literal(true)
  }).strict()).length(EXPECTED_CHECK_IDS.length),
  failures: z.array(z.never()).length(0),
  passed: z.literal(true),
  productionReady: z.literal(false)
}).strict();

export interface OrganizationReconciliationDevelopDualNodePreflightInput {
  readonly nodeId: string;
  readonly report: OrganizationReconciliationDevelopSourcePreflightReport;
}

export interface OrganizationReconciliationDevelopDualNodePreflightOptions {
  readonly expectedBuildRevision: string;
  readonly now: Date;
  readonly maxEvidenceAgeSeconds?: number;
  readonly maxNodeSkewSeconds?: number;
}

export interface OrganizationReconciliationDevelopDualNodePreflightReport {
  readonly contract: typeof ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_CONTRACT;
  readonly environment: "xrteeth-develop";
  readonly mode: "read-only";
  readonly assuranceScope: "structural-dual-node-source-preflight-only";
  readonly nodeIds: readonly [string, string];
  readonly windowStartedAt: string;
  readonly windowEndedAt: string;
  readonly buildRevision: string;
  readonly sourceCatalogSha256: string;
  readonly statementCatalogSha256: string;
  readonly iamPolicyChecksum: string;
  readonly alignedSourceSha256: string;
  readonly reportSetSha256: string;
  readonly componentCount: 3;
  readonly datasetProbeCount: 21;
  readonly sourcePreflightAligned: true;
  readonly collectorSignaturesVerified: false;
  readonly productionReady: false;
  readonly blockers: typeof ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_BLOCKERS;
}

/**
 * Aligns two already-sanitized Develop source-preflight reports. This proves
 * structural equality only. Node IDs are caller labels, not authenticated
 * collector identities, the expected build revision is caller supplied, and
 * the returned hashes are not signatures.
 */
export function createOrganizationReconciliationDevelopDualNodePreflightReport(
  candidateInputs: readonly [OrganizationReconciliationDevelopDualNodePreflightInput, OrganizationReconciliationDevelopDualNodePreflightInput],
  candidateOptions: OrganizationReconciliationDevelopDualNodePreflightOptions
): OrganizationReconciliationDevelopDualNodePreflightReport {
  const inputs = captureInputs(candidateInputs);
  const options = captureOptions(candidateOptions);
  if (inputs[0].nodeId === inputs[1].nodeId) fail();
  const reports = inputs.map((input) => parseReport(input.report)) as [
    z.infer<typeof sourceReportSchema>,
    z.infer<typeof sourceReportSchema>
  ];
  for (const report of reports) validateReportInvariants(report, options.expectedBuildRevision);

  const checkedAt = reports.map((report) => Date.parse(report.checkedAt));
  const now = options.now.getTime();
  const windowStartedAt = Math.min(...checkedAt);
  const windowEndedAt = Math.max(...checkedAt);
  if (
    windowEndedAt - windowStartedAt > options.maxNodeSkewSeconds * 1_000 ||
    windowEndedAt > now ||
    now - windowStartedAt > options.maxEvidenceAgeSeconds * 1_000
  ) fail();

  const stableLeft = stableReport(reports[0]);
  const stableRight = stableReport(reports[1]);
  if (canonicalJson(stableLeft) !== canonicalJson(stableRight)) fail();

  const nodeIds = [...inputs.map((input) => input.nodeId)].sort(compareUtf8) as [string, string];
  const orderedReports = [...inputs]
    .map((input, index) => ({ nodeId: input.nodeId, report: reports[index]! }))
    .sort((left, right) => compareUtf8(left.nodeId, right.nodeId));
  const alignedSourceSha256 = digest("aligned-source/v1", stableLeft);
  const reportSetSha256 = digest("report-set/v1", orderedReports);
  return Object.freeze({
    contract: ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_CONTRACT,
    environment: "xrteeth-develop",
    mode: "read-only",
    assuranceScope: "structural-dual-node-source-preflight-only",
    nodeIds: Object.freeze(nodeIds),
    windowStartedAt: new Date(windowStartedAt).toISOString(),
    windowEndedAt: new Date(windowEndedAt).toISOString(),
    buildRevision: reports[0].buildRevision,
    sourceCatalogSha256: reports[0].sourceCatalogSha256,
    statementCatalogSha256: reports[0].statementCatalogSha256,
    iamPolicyChecksum: reports[0].iamPolicyChecksum,
    alignedSourceSha256,
    reportSetSha256,
    componentCount: 3,
    datasetProbeCount: 21,
    sourcePreflightAligned: true,
    collectorSignaturesVerified: false,
    productionReady: false,
    blockers: ORGANIZATION_RECONCILIATION_DEVELOP_DUAL_NODE_PREFLIGHT_BLOCKERS
  });
}

function parseReport(candidate: unknown): z.infer<typeof sourceReportSchema> {
  const copied = captureJson(candidate, 0, { nodes: 0 });
  const result = sourceReportSchema.safeParse(copied);
  if (!result.success) fail();
  return result.data;
}

function validateReportInvariants(
  report: z.infer<typeof sourceReportSchema>,
  expectedBuildRevision: string
): void {
  if (report.buildRevision !== expectedBuildRevision) fail();
  const ids = report.components.map((component) => component.componentId);
  if (canonicalJson(ids) !== canonicalJson(["legacy-main", "identity", "plugin"])) fail();
  for (const component of report.components) {
    if (
      component.datasetProbeCount !== EXPECTED_DATASET_PROBE_COUNTS[component.componentId] ||
      component.nonEmptyDatasetProbeCount > component.datasetProbeCount ||
      component.observedColumnCount < component.requiredColumnCount ||
      canonicalJson(Object.keys(component.aggregateCounts).sort(compareUtf8)) !==
        canonicalJson(EXPECTED_AGGREGATE_KEYS[component.componentId])
    ) fail();
  }
  const checkIds = report.checks.map((check) => check.checkId).sort(compareUtf8);
  if (canonicalJson(checkIds) !== canonicalJson(EXPECTED_CHECK_IDS)) fail();
  if (
    report.legacyRbacScope.targetCount !== report.legacyRbacScope.presentTargetCount ||
    report.membershipSnapshotComparison.legacySubjectCount !==
      report.membershipSnapshotComparison.expectedSnapshotSubjectCount +
        report.membershipSnapshotComparison.protectedLegacySubjectCount ||
    report.membershipSnapshotComparison.expectedSnapshotSubjectCount !==
      report.membershipSnapshotComparison.snapshotSubjectCount
  ) fail();
}

function stableReport(report: z.infer<typeof sourceReportSchema>): unknown {
  const { checkedAt: _checkedAt, ...stable } = report;
  return stable;
}

function captureInputs(candidate: unknown): readonly [OrganizationReconciliationDevelopDualNodePreflightInput, OrganizationReconciliationDevelopDualNodePreflightInput] {
  if (!Array.isArray(candidate) || isProxy(candidate) || candidate.length !== 2) fail();
  if (Object.getOwnPropertySymbols(candidate).length > 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (!exactArrayDescriptors(descriptors, 2)) fail();
  const copied = [0, 1].map((index) => {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor)) fail();
    const input = exactObject(descriptor.value, ["nodeId", "report"]);
    if (typeof input.nodeId !== "string" || !IDENTIFIER.test(input.nodeId)) fail();
    return Object.freeze({ nodeId: input.nodeId, report: input.report as OrganizationReconciliationDevelopSourcePreflightReport });
  });
  return Object.freeze(copied) as unknown as readonly [OrganizationReconciliationDevelopDualNodePreflightInput, OrganizationReconciliationDevelopDualNodePreflightInput];
}

function captureOptions(candidate: unknown): Required<OrganizationReconciliationDevelopDualNodePreflightOptions> {
  const input = exactObject(candidate, ["expectedBuildRevision", "now", "maxEvidenceAgeSeconds", "maxNodeSkewSeconds"], true);
  if (typeof input.expectedBuildRevision !== "string" || !BUILD_REVISION.test(input.expectedBuildRevision)) fail();
  if (!(input.now instanceof Date) || !Number.isFinite(input.now.getTime())) fail();
  const maxEvidenceAgeSeconds = input.maxEvidenceAgeSeconds ?? 900;
  const maxNodeSkewSeconds = input.maxNodeSkewSeconds ?? 300;
  if (!safeBound(maxEvidenceAgeSeconds, 1, 3_600) || !safeBound(maxNodeSkewSeconds, 0, 900)) fail();
  return Object.freeze({
    expectedBuildRevision: input.expectedBuildRevision,
    now: new Date(input.now.getTime()),
    maxEvidenceAgeSeconds,
    maxNodeSkewSeconds
  });
}

function exactObject(candidate: unknown, keys: readonly string[], optional = false): Record<string, unknown> {
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate) || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  if (Object.getOwnPropertySymbols(candidate).length > 0) fail();
  const actual = Object.keys(descriptors).sort(compareUtf8);
  const allowed = [...keys].sort(compareUtf8);
  if (actual.some((key) => !allowed.includes(key)) || (!optional && canonicalJson(actual) !== canonicalJson(allowed))) fail();
  const output = Object.create(null) as Record<string, unknown>;
  for (const key of actual) {
    const descriptor = descriptors[key]!;
    if (!("value" in descriptor) || !descriptor.enumerable) fail();
    output[key] = descriptor.value;
  }
  return output;
}

function captureJson(candidate: unknown, depth: number, state: { nodes: number }): unknown {
  state.nodes += 1;
  if (state.nodes > 5_000 || depth > 12) fail();
  if (candidate === null || typeof candidate === "boolean") return candidate;
  if (typeof candidate === "string") {
    if (Buffer.byteLength(candidate, "utf8") > 8_192 || candidate.normalize("NFC") !== candidate) fail();
    return candidate;
  }
  if (typeof candidate === "number" && Number.isFinite(candidate)) return candidate;
  if (Array.isArray(candidate)) {
    if (isProxy(candidate) || candidate.length > 256) fail();
    if (Object.getOwnPropertySymbols(candidate).length > 0) fail();
    const descriptors = Object.getOwnPropertyDescriptors(candidate);
    if (!exactArrayDescriptors(descriptors, candidate.length)) fail();
    return Object.freeze(Array.from({ length: candidate.length }, (_, index) => {
      const descriptor = descriptors[String(index)]!;
      return captureJson((descriptor as PropertyDescriptor & { value: unknown }).value, depth + 1, state);
    }));
  }
  if (typeof candidate !== "object" || candidate === null || isProxy(candidate) || Object.getPrototypeOf(candidate) !== Object.prototype) fail();
  if (Object.getOwnPropertySymbols(candidate).length > 0) fail();
  const descriptors = Object.getOwnPropertyDescriptors(candidate);
  const keys = Object.keys(descriptors).sort(compareUtf8);
  if (keys.length > 128) fail();
  const output = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = descriptors[key]!;
    if (!("value" in descriptor) || !descriptor.enumerable) fail();
    output[key] = captureJson(descriptor.value, depth + 1, state);
  }
  return Object.freeze(output);
}

function exactArrayDescriptors(descriptors: Record<string, PropertyDescriptor>, length: number): boolean {
  const expected = ["length", ...Array.from({ length }, (_, index) => String(index))].sort(compareUtf8);
  const actual = Object.keys(descriptors).sort(compareUtf8);
  if (canonicalJson(actual) !== canonicalJson(expected)) return false;
  return Array.from({ length }, (_, index) => descriptors[String(index)])
    .every((descriptor) => descriptor !== undefined && "value" in descriptor && descriptor.enumerable);
}

function safeBound(candidate: unknown, minimum: number, maximum: number): candidate is number {
  return typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate >= minimum && candidate <= maximum;
}

function digest(domain: string, value: unknown): string {
  return createHash("sha256")
    .update("iam-organization-reconciliation:xrteeth-develop-dual-node-preflight:v1\u001f", "utf8")
    .update(domain, "utf8")
    .update("\u001f", "utf8")
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort(compareUtf8).map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  fail();
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function fail(): never {
  throw new Error("The dual-node Develop source preflight evidence is invalid or misaligned.");
}
