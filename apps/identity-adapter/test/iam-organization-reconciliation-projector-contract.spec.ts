import { describe, expect, it } from "vitest";
import {
  IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
  ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT,
  OrganizationSurfaceProjectorContractError,
  assertIndependentOrganizationSurfaceProjections,
  createOrganizationSurfaceProjectionBinding,
  executeIdentityOrganizationSurfaceProjector,
  executeLegacyOrganizationSurfaceProjector,
  isIdentityOrganizationSurfaceProjection,
  isLegacyOrganizationSurfaceProjection,
  isOrganizationSurfaceProjectionBinding,
  organizationSurfaceProjectorReadiness,
  type IdentityOrganizationSurfaceProjector,
  type LegacyOrganizationSurfaceProjector,
  type OrganizationSurfaceProjectionDraft
} from "../src/iam-organization-reconciliation-projector-contract.js";

const REGISTRY_SHA256 = "a".repeat(64);
const LEGACY_BUILD_SHA256 = "b".repeat(64);
const IDENTITY_BUILD_SHA256 = "c".repeat(64);

describe("organization surface projector contract", () => {
  it("keeps production projector readiness fail-closed", () => {
    expect(organizationSurfaceProjectorReadiness()).toEqual({
      ready: false,
      blockers: [
        "compiled-owner-semantic-registry-empty",
        "compiled-owner-semantic-registry-selection-not-implemented",
        "legacy-projector-not-registered",
        "identity-projector-not-registered",
        "independent-projector-artifact-provenance-not-attested",
        "projection-lineage-binding-not-integrated"
      ]
    });
  });

  it("uses disjoint runtime brands and detached result graphs even for one shared draft", async () => {
    const sharedDraft = draft("deny") as OrganizationSurfaceProjectionDraft;
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(sharedDraft),
      Object.freeze({ source: "legacy-test" }),
      REGISTRY_SHA256
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(sharedDraft),
      Object.freeze({ source: "identity-test" }),
      REGISTRY_SHA256
    );

    expect(isLegacyOrganizationSurfaceProjection(legacy)).toBe(true);
    expect(isIdentityOrganizationSurfaceProjection(legacy)).toBe(false);
    expect(isIdentityOrganizationSurfaceProjection(identity)).toBe(true);
    expect(isLegacyOrganizationSurfaceProjection(identity)).toBe(false);
    expect(legacy.surfaces).not.toBe(identity.surfaces);
    expect(legacy.surfaces.effectiveDecisions).not.toBe(identity.surfaces.effectiveDecisions);
    expect(Object.isFrozen(legacy)).toBe(true);
    expect(Object.isFrozen(legacy.surfaces)).toBe(true);
    expect(Object.isFrozen(legacy.surfaces.effectiveDecisions)).toBe(true);
    expect(() => assertIndependentOrganizationSurfaceProjections(legacy, identity)).not.toThrow();

    (sharedDraft.surfaces.effectiveDecisions as unknown as Array<{ decision: string }>)[0]!.decision = "allow";
    expect(legacy.surfaces.effectiveDecisions[0]!.decision).toBe("deny");
    expect(identity.surfaces.effectiveDecisions[0]!.decision).toBe("deny");
  });

  it("preserves independently produced differential decisions for downstream reconciliation", async () => {
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny")),
      {},
      REGISTRY_SHA256
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("allow")),
      {},
      REGISTRY_SHA256
    );
    assertIndependentOrganizationSurfaceProjections(legacy, identity);
    expect(legacy.surfaces.effectiveDecisions[0]!.decision).toBe("deny");
    expect(identity.surfaces.effectiveDecisions[0]!.decision).toBe("allow");
  });

  it("rejects one evaluator identity or build masquerading as both sides", async () => {
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny"), "test/shared-evaluator", LEGACY_BUILD_SHA256),
      {},
      REGISTRY_SHA256
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny"), "test/shared-evaluator", LEGACY_BUILD_SHA256),
      {},
      REGISTRY_SHA256
    );
    expect(() => assertIndependentOrganizationSurfaceProjections(legacy, identity))
      .toThrow(/disjoint origins and metadata/);
  });

  it("does not mistake metadata-disjoint wrappers around one callable for attested provenance", async () => {
    const sharedCallable = () => draft("deny");
    const legacy = await executeLegacyOrganizationSurfaceProjector({
      ...legacyProjector(draft("allow")),
      project: sharedCallable
    }, {}, REGISTRY_SHA256);
    const identity = await executeIdentityOrganizationSurfaceProjector({
      ...identityProjector(draft("allow")),
      project: sharedCallable
    }, {}, REGISTRY_SHA256);

    expect(() => assertIndependentOrganizationSurfaceProjections(legacy, identity)).not.toThrow();
    expect(organizationSurfaceProjectorReadiness().blockers).toContain(
      "independent-projector-artifact-provenance-not-attested"
    );
  });

  it("rejects registry A/B pairing and unbranded caller objects", async () => {
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny")),
      {},
      REGISTRY_SHA256
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny")),
      {},
      "d".repeat(64)
    );
    expect(() => assertIndependentOrganizationSurfaceProjections(legacy, identity))
      .toThrow(/same semantic registry/);

    expect(() => assertIndependentOrganizationSurfaceProjections(
      { ...legacy } as typeof legacy,
      identity
    )).toThrow(/trusted side brand/);
  });

  it("creates a detached frozen projection-binding/v1 for one exact lineage run", async () => {
    const lineageManifestSha256 = "d".repeat(64);
    const pluginSource = { sourceVersion: "plugin-v1", snapshotId: "plugin-snapshot-1" };
    const legacyPrimarySource = { sourceVersion: "legacy-v1", snapshotId: "legacy-snapshot-1" };
    const identityPrimarySource = { sourceVersion: "identity-v1", snapshotId: "identity-snapshot-1" };
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny")),
      {},
      REGISTRY_SHA256,
      { lineageManifestSha256, primarySource: legacyPrimarySource, pluginSource }
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny")),
      {},
      REGISTRY_SHA256,
      { lineageManifestSha256, primarySource: identityPrimarySource, pluginSource }
    );

    const binding = createOrganizationSurfaceProjectionBinding({
      legacyProjection: legacy,
      identityProjection: identity,
      semanticRegistrySha256: REGISTRY_SHA256,
      lineageManifestSha256,
      legacyPrimarySource,
      identityPrimarySource,
      pluginSource
    });
    expect(binding.contract).toBe(ORGANIZATION_SURFACE_PROJECTION_BINDING_CONTRACT);
    expect(isOrganizationSurfaceProjectionBinding(binding)).toBe(true);
    expect(binding.legacy.projectorContract).toBe(LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT);
    expect(binding.identity.projectorContract).toBe(IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT);
    expect(Object.isFrozen(binding)).toBe(true);
    expect(Object.isFrozen(binding.legacy)).toBe(true);
    expect(Object.isFrozen(binding.legacy.primarySource)).toBe(true);
    legacyPrimarySource.sourceVersion = "mutated";
    pluginSource.snapshotId = "mutated";
    expect(binding.legacy.primarySource.sourceVersion).toBe("legacy-v1");
    expect(binding.pluginSource.snapshotId).toBe("plugin-snapshot-1");
  });

  it("rejects projection run A with manifest B and cross-run A/B pairs", async () => {
    const manifestA = "d".repeat(64);
    const manifestB = "e".repeat(64);
    const plugin = { sourceVersion: "plugin-v1", snapshotId: "plugin-snapshot-1" };
    const legacySource = { sourceVersion: "legacy-v1", snapshotId: "legacy-snapshot-1" };
    const identitySource = { sourceVersion: "identity-v1", snapshotId: "identity-snapshot-1" };
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny")), {}, REGISTRY_SHA256,
      { lineageManifestSha256: manifestA, primarySource: legacySource, pluginSource: plugin }
    );
    const identityA = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny")), {}, REGISTRY_SHA256,
      { lineageManifestSha256: manifestA, primarySource: identitySource, pluginSource: plugin }
    );
    const identityB = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny"), "test/identity-b", "f".repeat(64)), {}, REGISTRY_SHA256,
      { lineageManifestSha256: manifestB, primarySource: identitySource, pluginSource: plugin }
    );
    const exact = {
      legacyProjection: legacy,
      identityProjection: identityA,
      semanticRegistrySha256: REGISTRY_SHA256,
      lineageManifestSha256: manifestA,
      legacyPrimarySource: legacySource,
      identityPrimarySource: identitySource,
      pluginSource: plugin
    };
    expect(() => createOrganizationSurfaceProjectionBinding({
      ...exact,
      lineageManifestSha256: manifestB
    })).toThrow(/run binding does not match/);
    expect(() => createOrganizationSurfaceProjectionBinding({
      ...exact,
      identityProjection: identityB
    })).toThrow(/run binding does not match/);
    expect(() => createOrganizationSurfaceProjectionBinding({
      ...exact,
      pluginSource: { ...plugin, snapshotId: "plugin-snapshot-2" }
    })).toThrow(/run binding does not match/);
  });

  it("rejects accessor-backed binding descriptors without invoking accessors", async () => {
    let getterInvoked = false;
    let projectorInvoked = false;
    const descriptor = {
      lineageManifestSha256: "d".repeat(64),
      primarySource: { sourceVersion: "legacy-v1", snapshotId: "legacy-snapshot-1" },
      pluginSource: { sourceVersion: "plugin-v1", snapshotId: "plugin-snapshot-1" }
    } as Record<string, unknown>;
    Object.defineProperty(descriptor, "lineageManifestSha256", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return "d".repeat(64);
      }
    });
    const projector = legacyProjector(draft("deny"));
    projector.project = () => {
      projectorInvoked = true;
      return draft("deny");
    };
    await expect(executeLegacyOrganizationSurfaceProjector(
      projector,
      {},
      REGISTRY_SHA256,
      descriptor as unknown as Parameters<typeof executeLegacyOrganizationSurfaceProjector>[3]
    )).rejects.toThrow(/data descriptors/);
    expect(getterInvoked).toBe(false);
    expect(projectorInvoked).toBe(false);
  });

  it("rejects the retired v1 side projector contract before invocation", async () => {
    let invoked = false;
    const projector = {
      ...legacyProjector(draft("deny")),
      contract: "iam-organization-legacy-surface-projector/v1",
      project: () => {
        invoked = true;
        return draft("deny");
      }
    } as unknown as LegacyOrganizationSurfaceProjector<unknown>;
    await expect(executeLegacyOrganizationSurfaceProjector(projector, {}, REGISTRY_SHA256))
      .rejects.toThrow(/side contract/);
    expect(invoked).toBe(false);
  });

  it("rejects a wrong side contract before invoking a projector", async () => {
    let invoked = false;
    const projector = {
      side: "identity",
      contract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
      evaluatorId: "test/legacy-evaluator",
      evaluatorBuildSha256: LEGACY_BUILD_SHA256,
      project: () => {
        invoked = true;
        return draft("deny");
      }
    } as unknown as LegacyOrganizationSurfaceProjector<unknown>;
    await expect(executeLegacyOrganizationSurfaceProjector(projector, {}, REGISTRY_SHA256))
      .rejects.toThrow(/side contract/);
    expect(invoked).toBe(false);
  });

  it("rejects an untrusted registry digest before invoking a projector", async () => {
    let invoked = false;
    const projector = legacyProjector(draft("deny"));
    projector.project = () => {
      invoked = true;
      return draft("deny");
    };
    await expect(executeLegacyOrganizationSurfaceProjector(projector, {}, "attacker"))
      .rejects.toThrow(/semantic registry digest/);
    expect(invoked).toBe(false);
  });

  it("rejects unknown or accessor-backed projection state", async () => {
    const unknownDraft = { ...draft("deny"), runtimeOverride: true };
    await expect(executeLegacyOrganizationSurfaceProjector(
      legacyProjector(unknownDraft as unknown as OrganizationSurfaceProjectionDraft),
      {},
      REGISTRY_SHA256
    )).rejects.toThrow(/unknown fields/);

    let invoked = false;
    const accessorDraft = {} as Record<string, unknown>;
    Object.defineProperty(accessorDraft, "surfaces", {
      enumerable: true,
      get: () => {
        invoked = true;
        return draft("deny").surfaces;
      }
    });
    await expect(executeLegacyOrganizationSurfaceProjector(
      legacyProjector(accessorDraft as unknown as OrganizationSurfaceProjectionDraft),
      {},
      REGISTRY_SHA256
    )).rejects.toThrow(/accessor/);
    expect(invoked).toBe(false);
  });

  it("descriptor-captures projector metadata once and rejects accessor TOCTOU", async () => {
    let getterInvoked = false;
    let projectInvoked = false;
    const accessorProjector = legacyProjector(draft("deny")) as unknown as Record<string, unknown>;
    Object.defineProperty(accessorProjector, "evaluatorId", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return "test/attacker";
      }
    });
    accessorProjector.project = () => {
      projectInvoked = true;
      return draft("deny");
    };
    await expect(executeLegacyOrganizationSurfaceProjector(
      accessorProjector as unknown as LegacyOrganizationSurfaceProjector<unknown>,
      {},
      REGISTRY_SHA256
    )).rejects.toThrow(/data descriptors/);
    expect(getterInvoked).toBe(false);
    expect(projectInvoked).toBe(false);

    const mutableProjector = legacyProjector(draft("deny"));
    let methodReceiver: unknown;
    mutableProjector.project = async function (this: {
      evaluatorId: string;
      evaluatorBuildSha256: string;
    }) {
      methodReceiver = this;
      await Promise.resolve();
      return draft(
        this.evaluatorId === "test/legacy-evaluator" &&
        this.evaluatorBuildSha256 === LEGACY_BUILD_SHA256
          ? "deny"
          : "allow"
      );
    };
    const pendingProjection = executeLegacyOrganizationSurfaceProjector(
      mutableProjector,
      {},
      REGISTRY_SHA256
    );
    (mutableProjector as { evaluatorId: string }).evaluatorId = "test/mutated";
    (mutableProjector as { evaluatorBuildSha256: string }).evaluatorBuildSha256 = "d".repeat(64);
    const projection = await pendingProjection;
    expect(projection.evaluatorId).toBe("test/legacy-evaluator");
    expect(projection.evaluatorBuildSha256).toBe(LEGACY_BUILD_SHA256);
    expect(projection.surfaces.effectiveDecisions[0]!.decision).toBe("deny");
    expect(methodReceiver).not.toBe(mutableProjector);
    expect(methodReceiver).toEqual({
      side: "legacy",
      contract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
      evaluatorId: "test/legacy-evaluator",
      evaluatorBuildSha256: LEGACY_BUILD_SHA256
    });
    expect(Object.isFrozen(methodReceiver)).toBe(true);
  });

  it.each([
    {
      name: "custom prototype",
      mutate: (projector: Record<PropertyKey, unknown>) =>
        Object.setPrototypeOf(projector, { attacker: true })
    },
    {
      name: "symbol field",
      mutate: (projector: Record<PropertyKey, unknown>) => {
        projector[Symbol("attacker")] = true;
      }
    },
    {
      name: "hidden field",
      mutate: (projector: Record<PropertyKey, unknown>) => {
        Object.defineProperty(projector, "hidden", { value: true, enumerable: false });
      }
    },
    {
      name: "unknown field",
      mutate: (projector: Record<PropertyKey, unknown>) => {
        projector.runtimeOverride = true;
      }
    }
  ])("rejects projector $name before invoking it", async ({ mutate }) => {
    let invoked = false;
    const projector = legacyProjector(draft("deny")) as unknown as Record<PropertyKey, unknown>;
    projector.project = () => {
      invoked = true;
      return draft("deny");
    };
    mutate(projector);
    await expect(executeLegacyOrganizationSurfaceProjector(
      projector as unknown as LegacyOrganizationSurfaceProjector<unknown>,
      {},
      REGISTRY_SHA256
    )).rejects.toThrow(/projector/);
    expect(invoked).toBe(false);
  });

  it("uses a specific contract error for pair safety failures", async () => {
    const legacy = await executeLegacyOrganizationSurfaceProjector(
      legacyProjector(draft("deny")),
      {},
      REGISTRY_SHA256
    );
    const identity = await executeIdentityOrganizationSurfaceProjector(
      identityProjector(draft("deny")),
      {},
      "e".repeat(64)
    );
    try {
      assertIndependentOrganizationSurfaceProjections(legacy, identity);
      throw new Error("expected failure");
    } catch (error) {
      expect(error).toBeInstanceOf(OrganizationSurfaceProjectorContractError);
    }
  });
});

function legacyProjector(
  projection: OrganizationSurfaceProjectionDraft,
  evaluatorId = "test/legacy-evaluator",
  evaluatorBuildSha256 = LEGACY_BUILD_SHA256
): LegacyOrganizationSurfaceProjector<unknown> {
  return {
    side: "legacy",
    contract: LEGACY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId,
    evaluatorBuildSha256,
    project: () => projection
  };
}

function identityProjector(
  projection: OrganizationSurfaceProjectionDraft,
  evaluatorId = "test/identity-evaluator",
  evaluatorBuildSha256 = IDENTITY_BUILD_SHA256
): IdentityOrganizationSurfaceProjector<unknown> {
  return {
    side: "identity",
    contract: IDENTITY_ORGANIZATION_SURFACE_PROJECTOR_CONTRACT,
    evaluatorId,
    evaluatorBuildSha256,
    project: () => projection
  };
}

function draft(decision: "allow" | "deny"): OrganizationSurfaceProjectionDraft {
  return {
    surfaces: {
      organizationDirectory: [
        { legacyOrganizationId: 1, name: "north", title: "North", active: true }
      ],
      organizationMappings: [
        { legacyOrganizationId: 1, identityOrganizationId: "legacy:1", active: true }
      ],
      memberships: [
        { subjectRef: "legacy-user:1", legacyOrganizationId: 1, active: true }
      ],
      organizationScopedRoles: [],
      pluginBindings: [],
      pluginVisibility: [],
      campusContexts: [],
      effectiveDecisions: [
        {
          subjectRef: "legacy-user:1",
          contextKind: "organization",
          contextRef: "legacy-org:1",
          resourceRef: "organization",
          capabilityRef: "organization.list",
          decision
        }
      ]
    }
  };
}
