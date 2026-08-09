import { describe, expect, it } from "vitest";
import {
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  OrganizationReconciliationInput,
  ReconciliationPair,
  validateOrganizationReconciliation
} from "../src/iam-organization-reconciliation-validator.js";

describe("work-package 4 full-scope organization reconciliation validator", () => {
  it("passes only when every required surface is complete and pairwise aligned", () => {
    const report = validateOrganizationReconciliation(alignedInput());

    expect(report).toMatchObject({
      dryRun: true,
      writeSideEffects: "none",
      evidencePolicy: "hash-only",
      assuranceScope: "collector-envelope-self-consistency",
      externalProvenanceRequired: true,
      staticChecksPassed: true,
      comparisonPolicy: "pairwise-no-union",
      severity: { P0: 0, P1: 0, P2: 0 },
      coverageBlockers: [],
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        coverageComplete: true,
        p0Blocks: true,
        p1Blocks: true,
        p2Classified: true,
        unionForbidden: true,
        externalProvenanceVerified: false,
        blockedReasons: ["external-provenance-required"]
      }
    });
    expect(report.coverage).toHaveLength(8);
    expect(report.coverage.every((surface) => surface.paginationComplete)).toBe(true);
    expect(report.reportHash).toMatch(/^[a-f0-9]{24}$/);
    expectNoRawEvidence(report);
  });

  it("classifies identity allow plus Legacy deny as P0 and never unions decisions", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair(
        [{ subjectRef: "private-user-581", pluginRef: "restricted-plugin", organizationRef: "test-university", decision: "deny" }],
        [{ subjectRef: "private-user-581", pluginRef: "restricted-plugin", organizationRef: "test-university", decision: "allow" }]
      )
    });

    expect(report.findings).toContainEqual(expect.objectContaining({
      surface: "plugin-visibility",
      severity: "P0",
      reasonCode: "identity-allow-legacy-deny"
    }));
    expect(report.severity.P0).toBe(1);
    expect(report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      unionForbidden: true,
      blockedReasons: ["p0-findings", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("private-user-581");
    expect(JSON.stringify(report)).not.toContain("restricted-plugin");
  });

  it("classifies Legacy allow plus Identity deny as P1", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      effectiveDecisions: pair(
        [{ subjectRef: "admin-operator", organizationRef: "test-university", resourceRef: "organization-list", capabilityRef: "read", decision: "allow" }],
        [{ subjectRef: "admin-operator", organizationRef: "test-university", resourceRef: "organization-list", capabilityRef: "read", decision: "deny" }]
      )
    });

    expect(report.findings).toContainEqual(expect.objectContaining({
      surface: "effective-decision",
      severity: "P1",
      reasonCode: "legacy-allow-identity-deny"
    }));
    expect(report.severity.P1).toBe(1);
    expect(report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      blockedReasons: ["p1-findings", "external-provenance-required"]
    });
  });

  it("keeps the explicitly allowlisted display title at classified P2", () => {
    const input = alignedInput();
    const legacyRecord = {
      legacyOrganizationId: 1,
      name: "test-university",
      title: "Legacy private title",
      active: true,
    };
    const identityRecord = {
      legacyOrganizationId: 1,
      name: "test-university",
      title: "Identity private title",
      active: true,
    };
    const report = validateOrganizationReconciliation({
      ...input,
      organizationDirectory: pair([legacyRecord], [identityRecord])
    });

    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-directory", severity: "P2", reasonCode: "display-only-mismatch" })
    ]));
    expect(report.severity).toMatchObject({ P0: 0, P1: 0, P2: 1 });
    expect(report).toMatchObject({
      staticChecksPassed: true,
      safetyGate: {
        passed: false,
        p2Classified: true,
        blockedReasons: ["external-provenance-required"]
      }
    });
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain("Legacy private title");
    expect(serialized).not.toContain("Identity private title");
  });

  it("blocks on a missing surface or any non-empty next cursor", () => {
    const { pluginBindings: _omitted, ...withoutPluginBindings } = alignedInput();
    const campus = withoutPluginBindings.campusContexts!;
    const report = validateOrganizationReconciliation({
      ...withoutPluginBindings,
      campusContexts: {
        legacy: campus.legacy,
        identity: {
          ...campus.identity!,
          nextCursor: "opaque-secret-next-page"
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-binding", code: "surface-missing" },
      { surface: "campus-context", code: "pagination-incomplete", side: "identity" }
    ]));
    expect(report.safetyGate).toMatchObject({
      passed: false,
      coverageComplete: false,
      blockedReasons: ["coverage-incomplete", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("opaque-secret-next-page");
  });

  it("blocks when source-version or pagination-completion evidence is absent", () => {
    const input = alignedInput();
    const membership = input.memberships!;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: {
          records: membership.legacy!.records,
          nextCursor: null
        },
        identity: {
          records: membership.identity!.records,
          sourceVersion: "identity-membership-v1"
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "source-version-missing", side: "legacy" },
      { surface: "membership", code: "pagination-state-missing", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
  });

  it("classifies extra authorization-bearing state as P0 and missing state as P1", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: pair(
        [
          { subjectRef: "private-user-581", legacyOrganizationId: 1, active: true },
          { subjectRef: "subject-a", legacyOrganizationId: 1, active: true },
          { subjectRef: "subject-b", legacyOrganizationId: 1, active: true }
        ],
        [
          { subjectRef: "private-user-581", legacyOrganizationId: 1, active: true },
          { subjectRef: "subject-a", legacyOrganizationId: 1, active: true },
          { subjectRef: "subject-c", legacyOrganizationId: 1, active: true }
        ]
      ),
      organizationMappings: pair(
        [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }],
        [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-wrong", active: true }]
      )
    });

    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "membership", severity: "P0", reasonCode: "identity-only-record" }),
      expect.objectContaining({ surface: "membership", severity: "P1", reasonCode: "identity-record-missing" }),
      expect.objectContaining({ surface: "organization-mapping", severity: "P0", reasonCode: "organization-id-mapping-mismatch" })
    ]));
    expect(report.safetyGate.blockedReasons).toEqual([
      "p0-findings",
      "p1-findings",
      "external-provenance-required"
    ]);
    expect(JSON.stringify(report)).not.toContain("identity-org-wrong");
    expect(JSON.stringify(report)).not.toContain("subject-c");
  });

  it("blocks ambiguous duplicate keys without exposing the duplicate identity", () => {
    const input = alignedInput();
    const duplicate = { subjectRef: "duplicate-private-subject", legacyOrganizationId: 1, active: true } as const;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: pair([duplicate, duplicate], [duplicate])
    });

    expect(report.coverageBlockers).toContainEqual(expect.objectContaining({
      surface: "membership",
      code: "duplicate-key",
      side: "legacy",
      entityHash: expect.stringMatching(/^[a-f0-9]{24}$/)
    }));
    expect(report.safetyGate).toMatchObject({ passed: false, coverageComplete: false });
    expect(JSON.stringify(report)).not.toContain("duplicate-private-subject");
  });

  it("blocks two Legacy organizations from reusing one Identity organization target", () => {
    const input = alignedInput();
    const ambiguous = [
      { legacyOrganizationId: 1, identityOrganizationId: "shared-private-identity-org", active: true },
      { legacyOrganizationId: 2, identityOrganizationId: "shared-private-identity-org", active: true }
    ] as const;
    const report = validateOrganizationReconciliation({
      ...input,
      organizationMappings: pair(ambiguous, ambiguous)
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      expect.objectContaining({ surface: "organization-mapping", code: "mapping-target-reused", side: "legacy" }),
      expect.objectContaining({ surface: "organization-mapping", code: "mapping-target-reused", side: "identity" })
    ]));
    expect(report.safetyGate).toMatchObject({ passed: false, coverageComplete: false });
    expect(JSON.stringify(report)).not.toContain("shared-private-identity-org");
  });

  it("blocks differing revisions instead of accepting a self-asserted equivalence", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        identity: { ...input.collectionEnvelope!.identity, sourceVersion: "identity-source-v2" }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "source-revision-mismatch" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
    expect(JSON.stringify(report)).not.toContain("identity-source-v2");
  });

  it("blocks a missing collector envelope and an internally truncated aggregate", () => {
    const input = alignedInput();
    const withoutEnvelope = validateOrganizationReconciliation({ ...input, collectionEnvelope: undefined });
    expect(withoutEnvelope.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "collection-envelope-missing"
    });
    expect(withoutEnvelope.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "evidence-nonce-invalid"
    });
    expect(withoutEnvelope.findings).toEqual([]);
    expect(JSON.stringify(withoutEnvelope)).not.toContain("private-user-581");
    expect(withoutEnvelope.safetyGate.passed).toBe(false);

    const membership = input.memberships!;
    const truncated = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: membership.legacy,
        identity: { ...membership.identity!, records: [] }
      }
    });
    expect(truncated.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "record-count-mismatch", side: "identity" },
      { surface: "membership", code: "page-record-hash-mismatch", side: "identity" },
      { surface: "membership", code: "aggregate-record-hash-mismatch", side: "identity" }
    ]));
    expect(truncated.safetyGate.passed).toBe(false);
  });

  it("accepts only null as the terminal cursor", () => {
    const input = alignedInput();
    const identity = input.memberships!.identity!;
    const report = validateOrganizationReconciliation({
      ...input,
      memberships: {
        legacy: input.memberships!.legacy,
        identity: {
          ...identity,
          nextCursor: " ",
          collection: {
            ...identity.collection!,
            pages: [{ ...identity.collection!.pages[0]!, nextCursor: " " }]
          }
        }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "membership", code: "pagination-incomplete", side: "identity" },
      { surface: "membership", code: "cursor-chain-invalid", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
  });

  it("hashes all raw evidence and produces deterministic output independent of record order", () => {
    const input = alignedInput();
    const membership = input.memberships!;
    const extra = { subjectRef: "secret-second-subject", legacyOrganizationId: 2, active: true } as const;
    const first = validateOrganizationReconciliation({
      ...input,
      memberships: pair([...membership.legacy!.records, extra], [...membership.identity!.records, extra])
    });
    const second = validateOrganizationReconciliation({
      ...input,
      memberships: pair([extra, ...membership.legacy!.records], [extra, ...membership.identity!.records])
    });

    expect(second).toEqual(first);
    expect(JSON.stringify(first)).not.toContain("secret-second-subject");
  });
});

function alignedInput(): OrganizationReconciliationInput {
  return {
    collectionEnvelope: collectionEnvelope(),
    organizationDirectory: pair(
      [{ legacyOrganizationId: 1, name: "test-university", title: "Private title", active: true }],
      [{ legacyOrganizationId: 1, name: "test-university", title: "Private title", active: true }]
    ),
    organizationMappings: pair(
      [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }],
      [{ legacyOrganizationId: 1, identityOrganizationId: "identity-org-one", active: true }]
    ),
    memberships: pair(
      [{ subjectRef: "private-user-581", legacyOrganizationId: 1, active: true }],
      [{ subjectRef: "private-user-581", legacyOrganizationId: 1, active: true }]
    ),
    organizationScopedRoles: pair(
      [{ subjectRef: "private-user-581", legacyOrganizationId: 1, roleRef: "private-role-alpha", active: true }],
      [{ subjectRef: "private-user-581", legacyOrganizationId: 1, roleRef: "private-role-alpha", active: true }]
    ),
    pluginBindings: pair(
      [{ pluginRef: "campus-plugin", bindingRef: "binding-one", organizationRef: "test-university", active: true }],
      [{ pluginRef: "campus-plugin", bindingRef: "binding-one", organizationRef: "test-university", active: true }]
    ),
    pluginVisibility: pair(
      [{ subjectRef: "private-user-581", pluginRef: "campus-plugin", organizationRef: "test-university", decision: "allow" }],
      [{ subjectRef: "private-user-581", pluginRef: "campus-plugin", organizationRef: "test-university", decision: "allow" }]
    ),
    campusContexts: pair(
      [{ subjectRef: "private-user-581", campusRef: "campus-one", organizationRef: "test-university", decision: "allow" }],
      [{ subjectRef: "private-user-581", campusRef: "campus-one", organizationRef: "test-university", decision: "allow" }]
    ),
    effectiveDecisions: pair(
      [{ subjectRef: "private-user-581", organizationRef: "test-university", resourceRef: "organization-one", capabilityRef: "read", decision: "allow" }],
      [{ subjectRef: "private-user-581", organizationRef: "test-university", resourceRef: "organization-one", capabilityRef: "read", decision: "allow" }]
    )
  };
}

function pair<T>(legacy: readonly T[], identity: readonly T[]): ReconciliationPair<T> {
  return {
    legacy: page(legacy, "legacy-snapshot-v1"),
    identity: page(identity, "identity-snapshot-v1")
  };
}

function page<T>(records: readonly T[], snapshotId: string) {
  const recordsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, records as never);
  return {
    records,
    sourceVersion: "source-v1",
    nextCursor: null,
    collection: {
      snapshotId,
      firstCursor: null,
      pageCount: 1,
      recordCount: records.length,
      recordsHash,
      pages: [{
        pageNumber: 1,
        requestCursor: null,
        nextCursor: null,
        recordOffset: 0,
        recordCount: records.length,
        recordsHash
      }]
    }
  } as const;
}

const EVIDENCE_NONCE = "a1".repeat(32);

function collectionEnvelope() {
  return {
    collectorContract: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
    collectorContractHash: ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "logical-snapshot-v1",
    windowId: "window-v1",
    windowStartedAt: "2026-08-09T00:00:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: { sourceVersion: "source-v1", snapshotId: "legacy-snapshot-v1" },
    identity: { sourceVersion: "source-v1", snapshotId: "identity-snapshot-v1" }
  } as const;
}

function expectNoRawEvidence(report: unknown): void {
  const serialized = JSON.stringify(report);
  for (const rawValue of [
    "test-university",
    "Private title",
    "identity-org-one",
    "private-user-581",
    "private-role-alpha",
    "campus-plugin",
    "binding-one",
    "campus-one",
    "organization-one",
    "source-v1"
  ]) {
    expect(serialized).not.toContain(rawValue);
  }
}
