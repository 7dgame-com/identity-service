import { describe, expect, it } from "vitest";
import {
  createOrganizationReconciliationEvidenceHash,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT,
  ORGANIZATION_RECONCILIATION_COLLECTOR_CONTRACT_HASH,
  ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
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
      realSourceAdaptersReady: false,
      staticChecksPassed: false,
      comparisonPolicy: "pairwise-no-union",
      severity: { P0: 0, P1: 0, P2: 0 },
      coverageBlockers: [{ surface: "collection-envelope", code: "real-source-adapters-not-ready" }],
      safetyGate: {
        passed: false,
        blocksDualWrite: true,
        coverageComplete: false,
        p0Blocks: true,
        p1Blocks: true,
        p2Classified: true,
        unionForbidden: true,
        externalProvenanceVerified: false,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
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
        [{ subjectRef: "private-user-581", pluginRef: "campus-plugin", organizationRef: "test-university", decision: "deny" }],
        [{ subjectRef: "private-user-581", pluginRef: "campus-plugin", organizationRef: "test-university", decision: "allow" }]
      )
    });

    expect(report.findings).toContainEqual(expect.objectContaining({
      surface: "plugin-visibility",
      severity: "P0",
      reasonCode: "identity-allow-legacy-deny"
    }));
    expect(report.severity.P0).toBe(1);
    expect(report.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "real-source-adapters-not-ready"
    });
    expect(report.safetyGate).toMatchObject({
      passed: false,
      blocksDualWrite: true,
      unionForbidden: true,
      blockedReasons: ["coverage-incomplete", "p0-findings", "external-provenance-required"]
    });
    expect(JSON.stringify(report)).not.toContain("private-user-581");
    expect(JSON.stringify(report)).not.toContain("campus-plugin");
  });

  it("classifies Legacy allow plus Identity deny as P1", () => {
    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      effectiveDecisions: pair(
        [{ subjectRef: "private-user-581", organizationRef: "test-university", resourceRef: "organization-one", capabilityRef: "read", decision: "allow" }],
        [{ subjectRef: "private-user-581", organizationRef: "test-university", resourceRef: "organization-one", capabilityRef: "read", decision: "deny" }]
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
      blockedReasons: ["coverage-incomplete", "p1-findings", "external-provenance-required"]
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
      staticChecksPassed: false,
      safetyGate: {
        passed: false,
        p2Classified: true,
        blockedReasons: ["coverage-incomplete", "external-provenance-required"]
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
      "coverage-incomplete",
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

  it("allows heterogeneous source-owned revisions but blocks a changed per-side envelope revision", () => {
    const aligned = validateOrganizationReconciliation(alignedInput());
    expect(aligned.coverageBlockers).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "source-version-envelope-mismatch" })
    ]));

    const input = alignedInput();
    const report = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        identity: { ...input.collectionEnvelope!.identity, sourceVersion: "identity-source-v2" }
      }
    });

    expect(report.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "organization-directory", code: "source-version-envelope-mismatch", side: "identity" },
      { surface: "effective-decision", code: "source-version-envelope-mismatch", side: "identity" }
    ]));
    expect(report.safetyGate.passed).toBe(false);
    expect(JSON.stringify(report)).not.toContain("identity-source-v2");
  });

  it("requires a reviewed collector build and the same complete subject universe on both sides", () => {
    const input = alignedInput();
    const invalidBuild = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: { ...input.collectionEnvelope!, collectorBuildRevision: "short" }
    });
    expect(invalidBuild.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "collector-build-revision-invalid"
    });

    const secondSubject = "zero-membership-private-subject";
    const expandedHash = createOrganizationReconciliationEvidenceHash(
      EVIDENCE_NONCE,
      ["private-user-581", secondSubject].sort()
    );
    const expandedDecisionUniverses = {
      pluginVisibility: decisionUniverse([
        ["private-user-581", "campus-plugin", "test-university"],
        [secondSubject, "campus-plugin", "test-university"]
      ], {
        subjects: ["private-user-581", secondSubject],
        plugins: ["campus-plugin"],
        organizations: ["test-university"]
      }),
      campusContexts: decisionUniverse([
        ["private-user-581", "campus-one"],
        [secondSubject, "campus-one"]
      ], {
        subjects: ["private-user-581", secondSubject],
        campuses: ["campus-one"],
        organizations: ["test-university"]
      }),
      effectiveDecisions: decisionUniverse([
        ["private-user-581", "test-university", "organization-one", "read"],
        [secondSubject, "test-university", "organization-one", "read"]
      ], {
        subjects: ["private-user-581", secondSubject],
        organizations: ["test-university"],
        resources: ["organization-one"],
        capabilities: ["read"]
      })
    };
    const omittedSubject = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash },
          decisionUniverses: expandedDecisionUniverses
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash },
          decisionUniverses: expandedDecisionUniverses
        }
      }
    });
    expect(omittedSubject.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "plugin-visibility", code: "decision-universe-coverage-mismatch", side: "legacy" },
      { surface: "campus-context", code: "decision-universe-coverage-mismatch", side: "identity" },
      { surface: "effective-decision", code: "decision-universe-coverage-mismatch", side: "legacy" }
    ]));
    expect(omittedSubject.safetyGate.passed).toBe(false);
    expect(JSON.stringify(omittedSubject)).not.toContain(secondSubject);

    const mismatchedSides = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        }
      }
    });
    expect(mismatchedSides.coverageBlockers).toContainEqual({
      surface: "collection-envelope",
      code: "subject-universe-side-mismatch"
    });
  });

  it("accepts an internally valid attested empty dimension while retaining the real-adapter blocker", () => {
    const input = alignedInput();
    const emptyUniverse = decisionUniverse([], {
      subjects: ["private-user-581"],
      plugins: [],
      organizations: ["test-university"]
    });
    const report = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair([], []),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: emptyUniverse
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            pluginVisibility: emptyUniverse
          }
        }
      }
    });
    expect(report.coverageBlockers).toEqual([
      { surface: "collection-envelope", code: "real-source-adapters-not-ready" }
    ]);
    expect(report.staticChecksPassed).toBe(false);
    expect(report.safetyGate.blockedReasons).toEqual([
      "coverage-incomplete",
      "external-provenance-required"
    ]);
  });

  it("rejects self-reported decision dimensions that are missing, changed, or falsely empty", () => {
    const input = alignedInput();
    const pluginUniverse = input.collectionEnvelope!.legacy.decisionUniverses.pluginVisibility;
    const missingDimension = {
      ...pluginUniverse,
      dimensions: { ...pluginUniverse.dimensions }
    } as { dimensions: Record<string, unknown> } & typeof pluginUniverse;
    delete missingDimension.dimensions.plugins;
    const missing = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: missingDimension
          }
        }
      }
    });
    expect(missing.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "collection-envelope", code: "decision-universe-side-mismatch" }
    ]));

    const changed = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            effectiveDecisions: {
              ...input.collectionEnvelope!.legacy.decisionUniverses.effectiveDecisions,
              derivationBuildRevision: "b".repeat(40),
              dimensions: {
                ...input.collectionEnvelope!.legacy.decisionUniverses.effectiveDecisions.dimensions,
                capabilities: { count: 1, hash: "b".repeat(64) }
              }
            }
          }
        }
      }
    });
    expect(changed.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "effective-decision", code: "decision-dimension-coverage-mismatch", side: "legacy" }
    ]));

    const falselyEmpty = decisionUniverse([], {
      subjects: ["private-user-581"],
      plugins: ["campus-plugin"],
      organizations: ["test-university"]
    });
    const emptyReport = validateOrganizationReconciliation({
      ...input,
      pluginVisibility: pair([], []),
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          decisionUniverses: {
            ...input.collectionEnvelope!.legacy.decisionUniverses,
            pluginVisibility: falselyEmpty
          }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          decisionUniverses: {
            ...input.collectionEnvelope!.identity.decisionUniverses,
            pluginVisibility: falselyEmpty
          }
        }
      }
    });
    expect(emptyReport.coverageBlockers).toEqual(expect.arrayContaining([
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "legacy" },
      { surface: "collection-envelope", code: "decision-universe-derivation-invalid", side: "identity" }
    ]));
  });

  it("blocks a non-empty decision surface when its records and key universe omit a subject", () => {
    const input = alignedInput();
    const secondSubject = "zero-membership-private-subject";
    const expandedHash = createOrganizationReconciliationEvidenceHash(
      EVIDENCE_NONCE,
      ["private-user-581", secondSubject].sort()
    );
    const report = validateOrganizationReconciliation({
      ...input,
      collectionEnvelope: {
        ...input.collectionEnvelope!,
        legacy: {
          ...input.collectionEnvelope!.legacy,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        },
        identity: {
          ...input.collectionEnvelope!.identity,
          subjectUniverse: { subjectCount: 2, subjectsHash: expandedHash }
        }
      }
    });

    for (const surface of ["plugin-visibility", "campus-context", "effective-decision"] as const) {
      expect(report.coverageBlockers).toEqual(expect.arrayContaining([
        { surface, code: "decision-subject-universe-coverage-mismatch", side: "legacy" },
        { surface, code: "decision-subject-universe-coverage-mismatch", side: "identity" }
      ]));
    }
    expect(report.safetyGate.passed).toBe(false);
    expect(JSON.stringify(report)).not.toContain(secondSubject);
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
    legacy: page(legacy, "legacy-source-v1", "legacy-snapshot-v1"),
    identity: page(identity, "identity-source-v1", "identity-snapshot-v1")
  };
}

function page<T>(records: readonly T[], sourceVersion: string, snapshotId: string) {
  const recordsHash = createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, records as never);
  return {
    records,
    sourceVersion,
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
    collectorBuildRevision: COLLECTOR_BUILD_REVISION,
    evidenceNonce: EVIDENCE_NONCE,
    logicalSnapshotId: "logical-snapshot-v1",
    windowId: "window-v1",
    windowStartedAt: "2026-08-09T00:00:00.000Z",
    windowEndedAt: "2026-08-09T00:05:00.000Z",
    legacy: {
      sourceVersion: "legacy-source-v1",
      snapshotId: "legacy-snapshot-v1",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    },
    identity: {
      sourceVersion: "identity-source-v1",
      snapshotId: "identity-snapshot-v1",
      subjectUniverse: { subjectCount: 1, subjectsHash: SUBJECT_UNIVERSE_HASH },
      decisionUniverses: DECISION_UNIVERSES
    }
  } as const;
}

const COLLECTOR_BUILD_REVISION = "a".repeat(40);
const SUBJECT_UNIVERSE_HASH = createOrganizationReconciliationEvidenceHash(
  EVIDENCE_NONCE,
  ["private-user-581"]
);
const DECISION_UNIVERSES = {
  pluginVisibility: decisionUniverse(
    [["private-user-581", "campus-plugin", "test-university"]],
    { subjects: ["private-user-581"], plugins: ["campus-plugin"], organizations: ["test-university"] }
  ),
  campusContexts: decisionUniverse(
    [["private-user-581", "campus-one"]],
    { subjects: ["private-user-581"], campuses: ["campus-one"], organizations: ["test-university"] }
  ),
  effectiveDecisions: decisionUniverse(
    [["private-user-581", "test-university", "organization-one", "read"]],
    {
      subjects: ["private-user-581"],
      organizations: ["test-university"],
      resources: ["organization-one"],
      capabilities: ["read"]
    }
  )
};

function decisionUniverse(
  keys: readonly (readonly string[])[],
  dimensions: Readonly<Record<string, readonly string[]>>
) {
  const canonicalKeys = [...new Set(keys.map((key) => JSON.stringify(key)))].sort();
  return {
    keyCount: canonicalKeys.length,
    keysHash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalKeys),
    derivationContract: ORGANIZATION_RECONCILIATION_DECISION_DERIVATION_CONTRACT,
    derivationBuildRevision: COLLECTOR_BUILD_REVISION,
    dimensions: Object.fromEntries(Object.entries(dimensions).map(([name, values]) => {
      const canonicalValues = [...new Set(values)].sort();
      return [name, {
        count: canonicalValues.length,
        hash: createOrganizationReconciliationEvidenceHash(EVIDENCE_NONCE, canonicalValues)
      }];
    }))
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
    "legacy-source-v1",
    "identity-source-v1"
  ]) {
    expect(serialized).not.toContain(rawValue);
  }
}
