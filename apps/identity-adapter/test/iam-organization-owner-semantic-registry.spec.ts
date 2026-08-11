import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_OWNER_DEVELOP_APPROVAL,
  ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
  ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE,
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS,
  ORGANIZATION_OWNER_DEVELOP_DECISION_PINS,
  ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256,
  assertOrganizationOwnerDevelopDecisionCatalogReviewPins,
  canonicalizeOrganizationOwnerSemanticRegistry,
  findCompiledOrganizationOwnerSemanticRegistry,
  organizationOwnerSemanticRegistryCandidateBlockers,
  organizationOwnerSemanticRegistryReadiness
} from "../src/iam-organization-owner-semantic-registry.js";
import {
  OrganizationReconciliationProvenRuleError,
  calculateRuleFreeYiiRbacClosure,
  canonicalSystemAdminPluginId,
  classifyStrictPluginOrganizationBinding,
  identityOrganizationIdForCanonicalLegacyId,
  legacySubjectLifecycleFromStatus,
  pluginAccessScopeAllows,
  requireStrictPluginAccessScope
} from "../src/iam-organization-reconciliation-pure-rules.js";
import {
  reviewedTestOrganizationOwnerSemanticRegistryInput
} from "./fixtures/iam-organization-owner-semantic-registry.js";

describe("organization owner semantic registry", () => {
  it("keeps the production registry compiled-empty and immune to process input", () => {
    const previous = process.env.IDENTITY_ORGANIZATION_OWNER_SEMANTIC_REGISTRY;
    process.env.IDENTITY_ORGANIZATION_OWNER_SEMANTIC_REGISTRY = JSON.stringify(
      reviewedTestOrganizationOwnerSemanticRegistryInput()
    );
    process.argv.push("--organization-owner-semantic-registry=allow");
    try {
      expect(organizationOwnerSemanticRegistryReadiness()).toEqual({
        ready: false,
        compiledRegistryCount: 0,
        blockers: [
          "compiled-owner-semantic-registry-empty",
          "identity-shadow-candidate-selectors-owner-decision-missing",
          "role-scope-owner-decision-missing",
          "plugin-overlay-owner-decision-missing",
          "campus-public-context-owner-decision-missing",
          "capability-catalog-owner-decision-missing"
        ]
      });
    } finally {
      process.argv.pop();
      if (previous === undefined) delete process.env.IDENTITY_ORGANIZATION_OWNER_SEMANTIC_REGISTRY;
      else process.env.IDENTITY_ORGANIZATION_OWNER_SEMANTIC_REGISTRY = previous;
    }
  });

  it("canonicalizes, detaches, deeply freezes, and domain-hashes one reviewed candidate", () => {
    const input = reviewedTestOrganizationOwnerSemanticRegistryInput();
    const canonical = canonicalizeOrganizationOwnerSemanticRegistry(input);
    (input as { registryId: string }).registryId = "test/mutated";
    expect(canonical.registryId).toBe("test/wp4/foundation-only");
    expect(canonical.registrySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(canonical)).toBe(true);
    expect(Object.isFrozen(canonical.ownerDecisions)).toBe(true);
    expect(canonicalizeOrganizationOwnerSemanticRegistry(
      reviewedTestOrganizationOwnerSemanticRegistryInput()
    ).registrySha256).toBe(canonical.registrySha256);
    expect(organizationOwnerSemanticRegistryCandidateBlockers(canonical)).toEqual([
      "identity-shadow-candidate-selectors-owner-decision-missing",
      "role-scope-owner-decision-missing",
      "plugin-overlay-owner-decision-missing",
      "campus-public-context-owner-decision-missing",
      "capability-catalog-owner-decision-missing"
    ]);
    expect(findCompiledOrganizationOwnerSemanticRegistry(canonical.registrySha256)).toBeUndefined();
  });

  it("records the user-approved Develop recommendation without promoting production readiness", () => {
    expect(ORGANIZATION_OWNER_DEVELOP_APPROVAL).toMatchObject({
      environment: "xrteeth-develop",
      direction: "identity-native-replacement",
      writesAuthorized: false,
      productionAuthorized: false
    });
    expect(ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256).toMatch(/^[a-f0-9]{64}$/);
    expect(organizationOwnerSemanticRegistryCandidateBlockers(
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE
    )).toEqual([]);
    expect(Object.values(ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.ownerDecisions))
      .not.toContain(null);
    expect(findCompiledOrganizationOwnerSemanticRegistry(
      ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE.registrySha256
    )).toBeUndefined();
    expect(organizationOwnerSemanticRegistryReadiness().ready).toBe(false);
  });

  it("compiles the exact owner-bound Develop-only read-only execution catalogs", () => {
    const { pluginOverlay, campusPublicContext, capabilityCatalog } =
      ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS;

    expect(pluginOverlay).toMatchObject({
      decisionState: "owner-bound",
      staticArtifact: {
        path: "web/public/config/plugins.json",
        sha256: "724bcb509672a0f2266a5748f08b71d52b099f7e636098c8573eaa115878bf8c",
        evidenceBoundary: "source-tree-proposal-not-deployment-proof"
      },
      requiredAuthorizationFields: ["id", "enabled", "accessScope", "organizationName"],
      deploymentArtifactDigest: "required-separate-runtime-evidence"
    });
    expect(pluginOverlay.staticBuiltIns).toEqual([
      { id: "system-admin", enabled: true, accessScope: "root-only", organizationName: null },
      { id: "user-management", enabled: true, accessScope: "root-only", organizationName: null }
    ]);

    expect(campusPublicContext).toMatchObject({
      decisionState: "owner-bound",
      executionState: "owner-bound-campus-context-decision-execution",
      canonicalMarkers: { platformGlobal: "org:platform-global", public: "org:public" },
      reservedOrganizationSlugs: ["platform-global", "public"],
      contextClassifier: {
        state: "owner-bound",
        contextKinds: ["organization", "platform-global", "public"]
      },
      organizationMatch: {
        positiveId: "exact-id-first-and-exclusive",
        slugFallback: "only-when-both-ids-absent-exact-canonical-lowercase",
        idNameConflict: "deny"
      },
      summaryRule: {
        evaluator: "any-exact-campus-capability-allow",
        missingCapability: "P1-block"
      }
    });
    expect(campusPublicContext.summaryRule.requiredCapabilityIds).toHaveLength(9);
    expect(campusPublicContext.capabilityRules).toHaveLength(9);
    expect(campusPublicContext.capabilityRules.every((rule) => rule.bindingState === "owner-bound"))
      .toBe(true);

    expect(capabilityCatalog.decisionState).toBe("owner-bound");
    expect(capabilityCatalog.executionState)
      .toBe("owner-bound-context-decision-execution");
    expect(capabilityCatalog.entries).toHaveLength(20);
    expect(new Set(capabilityCatalog.entries.map((entry) =>
      `${entry.resourceId}\u0000${entry.capabilityId}`
    ))).toHaveLength(20);
    expect(capabilityCatalog.entries.filter((entry) => entry.surface === "campus")).toHaveLength(9);
    expect(capabilityCatalog.entries.filter((entry) => entry.surface === "legacy-organization-api"))
      .toHaveLength(4);
    expect(capabilityCatalog.entries.filter((entry) => entry.surface === "legacy-organization-api")
      .every((entry) =>
        entry.decisionRule === "live-yii-rule-free-permission" &&
        JSON.stringify(entry.scope) === JSON.stringify(["platform-global"]) &&
        entry.targetSpecificConstraints === "excluded-separate-evaluator"
      )).toBe(true);
    const userManagement = capabilityCatalog.entries.filter(
      (entry) => entry.surface === "user-management"
    );
    expect(userManagement).toHaveLength(7);
    expect(userManagement.every((entry) =>
      entry.bindingState === "owner-bound" &&
      entry.decisionRule === "verified-root-and-live-yii-permission" &&
      JSON.stringify(entry.scope) === JSON.stringify(["platform-global"]) &&
      entry.targetSpecificConstraints === "excluded-separate-evaluator"
    )).toBe(true);
    expect(capabilityCatalog.legacyEvaluator.state).toBe("owner-bound");
    expect(capabilityCatalog.identityEvaluator.state).toBe("owner-bound");
    expect(capabilityCatalog.userManagementEvaluatorChoice).toMatchObject({
      state: "owner-bound",
      recommended: "frontend-verified-root-and-backend-live-yii-permission"
    });
    expect(Object.isFrozen(capabilityCatalog.entries[0]!.roles)).toBe(true);
    expect(Object.isFrozen(capabilityCatalog.entries[0]!.actions)).toBe(true);
  });

  it("pins all five reviewed catalog literals independently and rejects semantic drift", () => {
    expect(ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256).toEqual({
      identityShadowCandidateSelectors:
        "e3ed89538a845200bb4dcfdcea113f1d940cd5a802b865929bad9f63933117a8",
      roleScopes: "0ebfed46d3699c2c508a5f49fa91da5b5c963afb8048d7639ec577abc720bfff",
      pluginOverlay: "753e82c0a84e820d279a309f9f23fb99987c26ac7072c09ba0cb23eccc28fadd",
      campusPublicContext: "51280ce6bf0b1e54118011eac9bb5c08068eaef38d8042ce6fd2db44587a3347",
      capabilityCatalog: "19357bafa8d4cfbb2070b8f33bcb8bbcb820c7efbe9e40b8f13ce3435ac88d97"
    });
    expect(Object.fromEntries(Object.entries(ORGANIZATION_OWNER_DEVELOP_DECISION_PINS)
      .map(([name, pin]) => [name, pin.catalogSha256])))
      .toEqual(ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256);
    expect(() => assertOrganizationOwnerDevelopDecisionCatalogReviewPins(
      ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
    )).not.toThrow();

    for (const name of [
      "identityShadowCandidateSelectors",
      "roleScopes",
      "pluginOverlay",
      "campusPublicContext",
      "capabilityCatalog"
    ] as const) {
      const driftedCatalogs = {
        ...ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS,
        [name]: {
          ...ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS[name],
          reviewedLiteralDrift: true
        }
      };
      expect(() => assertOrganizationOwnerDevelopDecisionCatalogReviewPins(driftedCatalogs))
        .toThrow(new RegExp(`${name}.*independently reviewed literal SHA-256`));
    }
    expect(() => assertOrganizationOwnerDevelopDecisionCatalogReviewPins({
      ...ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS,
      runtimeOverride: true
    })).toThrow(/missing or unknown catalogs/);
  });

  it("rejects primitive overrides, unknown state, accessors, and hidden state", () => {
    const overridden = reviewedTestOrganizationOwnerSemanticRegistryInput() as unknown as Record<string, unknown>;
    overridden.primitives = {
      ...(overridden.primitives as Record<string, unknown>),
      legacySubjectLifecycleContract: "status-1-active"
    };
    expect(() => canonicalizeOrganizationOwnerSemanticRegistry(overridden)).toThrow(/cannot be overridden/);

    const unknown = reviewedTestOrganizationOwnerSemanticRegistryInput() as unknown as Record<string, unknown>;
    unknown.runtimeOverride = true;
    expect(() => canonicalizeOrganizationOwnerSemanticRegistry(unknown)).toThrow(/unknown fields/);

    let invoked = false;
    const accessor = reviewedTestOrganizationOwnerSemanticRegistryInput() as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "registryId", {
      enumerable: true,
      get: () => {
        invoked = true;
        return "test/attacker";
      }
    });
    expect(() => canonicalizeOrganizationOwnerSemanticRegistry(accessor)).toThrow(/accessor/);
    expect(invoked).toBe(false);

    const hidden = reviewedTestOrganizationOwnerSemanticRegistryInput();
    Object.defineProperty(hidden.ownerDecisions, "hiddenApproval", {
      enumerable: false,
      value: "approved"
    });
    expect(() => canonicalizeOrganizationOwnerSemanticRegistry(hidden)).toThrow(/hidden/);
  });
});

describe("organization reconciliation proven pure rules", () => {
  it("uses the exact deterministic Legacy compatibility mapping", () => {
    expect(identityOrganizationIdForCanonicalLegacyId(17)).toBe("legacy:17");
    expect(identityOrganizationIdForCanonicalLegacyId("17")).toBe("legacy:17");
    expect(() => identityOrganizationIdForCanonicalLegacyId("017")).toThrow(/invalid/);
    expect(() => identityOrganizationIdForCanonicalLegacyId(0)).toThrow(/invalid/);
  });

  it("maps only numeric Legacy status 10 to active", () => {
    expect(legacySubjectLifecycleFromStatus(10)).toEqual({
      legacyStatus: 10,
      active: true,
      identityStatus: "active"
    });
    expect(legacySubjectLifecycleFromStatus(0)).toEqual({
      legacyStatus: 0,
      active: false,
      identityStatus: "inactive"
    });
    expect(legacySubjectLifecycleFromStatus(9).active).toBe(false);
    expect(() => legacySubjectLifecycleFromStatus("10")).toThrow(/safe integer/);
  });

  it("enforces plugin ID, access scope, and SQL-NULL-only public semantics", () => {
    expect(canonicalSystemAdminPluginId("campus-2")).toBe("campus-2");
    expect(() => canonicalSystemAdminPluginId("campus_2")).toThrow(/canonical ID/);
    expect(() => canonicalSystemAdminPluginId(" campus ")).toThrow(/canonical/);
    expect(requireStrictPluginAccessScope("manager-only")).toBe("manager-only");
    expect(() => requireStrictPluginAccessScope("staff-only")).toThrow(/invalid/);
    expect(classifyStrictPluginOrganizationBinding(null)).toEqual({
      kind: "public",
      organizationName: null,
      organizationRef: "org:public"
    });
    expect(classifyStrictPluginOrganizationBinding("north")).toEqual({
      kind: "organization-name",
      organizationName: "north"
    });
    expect(() => classifyStrictPluginOrganizationBinding("")).toThrow(/canonical/);
    expect(() => classifyStrictPluginOrganizationBinding(" north ")).toThrow(/canonical/);
    expect(() => classifyStrictPluginOrganizationBinding(undefined)).toThrow(/invalid/);
  });

  it("applies the exact recognized host role levels without granting unknown roles", () => {
    expect(pluginAccessScopeAllows("auth-only", { authenticated: true, roles: ["user"] })).toBe(true);
    expect(pluginAccessScopeAllows("manager-only", { authenticated: true, roles: ["manager"] })).toBe(true);
    expect(pluginAccessScopeAllows("admin-only", { authenticated: true, roles: ["manager"] })).toBe(false);
    expect(pluginAccessScopeAllows("root-only", { authenticated: true, roles: ["root"] })).toBe(true);
    expect(pluginAccessScopeAllows("auth-only", { authenticated: true, roles: ["custom-role"] })).toBe(false);
    expect(pluginAccessScopeAllows("auth-only", { authenticated: false, roles: ["root"] })).toBe(false);
  });

  it("computes nested rule-free Yii RBAC closure including direct permissions", () => {
    const closure = calculateRuleFreeYiiRbacClosure({
      rules: [],
      items: [
        { name: "admin", type: "role", ruleName: null },
        { name: "manager", type: "role", ruleName: null },
        { name: "organization.update", type: "permission", ruleName: null },
        { name: "organization.list", type: "permission", ruleName: null }
      ],
      relations: [
        { parent: "admin", child: "manager" },
        { parent: "manager", child: "organization.update" }
      ]
    }, ["admin", "organization.list"]);
    expect(closure).toEqual({
      directAssignments: ["admin", "organization.list"],
      roles: ["admin", "manager"],
      permissions: ["organization.list", "organization.update"],
      visitedItems: ["admin", "manager", "organization.list", "organization.update"]
    });
    expect(Object.isFrozen(closure)).toBe(true);
    expect(Object.isFrozen(closure.permissions)).toBe(true);
  });

  it.each([
    {
      name: "duplicate item",
      graph: {
        rules: [],
        items: [
          { name: "a", type: "role", ruleName: null },
          { name: "a", type: "role", ruleName: null }
        ],
        relations: []
      },
      assignments: ["a"],
      code: "duplicate-rbac-item"
    },
    {
      name: "duplicate relation",
      graph: {
        rules: [],
        items: [
          { name: "a", type: "role", ruleName: null },
          { name: "b", type: "permission", ruleName: null }
        ],
        relations: [
          { parent: "a", child: "b" },
          { parent: "a", child: "b" }
        ]
      },
      assignments: ["a"],
      code: "duplicate-rbac-relation"
    },
    {
      name: "named Yii rule",
      graph: {
        rules: [],
        items: [{ name: "admin", type: "role", ruleName: "ownerRule" }],
        relations: []
      },
      assignments: ["admin"],
      code: "unsupported-yii-rule"
    },
    {
      name: "cycle",
      graph: {
        rules: [],
        items: [
          { name: "a", type: "role", ruleName: null },
          { name: "b", type: "role", ruleName: null }
        ],
        relations: [{ parent: "a", child: "b" }, { parent: "b", child: "a" }]
      },
      assignments: ["a"],
      code: "rbac-cycle"
    },
    {
      name: "missing relation item",
      graph: {
        rules: [],
        items: [{ name: "a", type: "role", ruleName: null }],
        relations: [{ parent: "a", child: "missing" }]
      },
      assignments: ["a"],
      code: "missing-rbac-item"
    },
    {
      name: "unknown assignment",
      graph: {
        rules: [],
        items: [{ name: "a", type: "role", ruleName: null }],
        relations: []
      },
      assignments: ["missing"],
      code: "missing-rbac-item"
    },
    {
      name: "duplicate assignment",
      graph: {
        rules: [],
        items: [{ name: "a", type: "role", ruleName: null }],
        relations: []
      },
      assignments: ["a", "a"],
      code: "duplicate-rbac-assignment"
    }
  ])("fails closed for $name", ({ graph, assignments, code }) => {
    try {
      calculateRuleFreeYiiRbacClosure(graph, assignments);
      throw new Error("expected failure");
    } catch (error) {
      expect(error).toBeInstanceOf(OrganizationReconciliationProvenRuleError);
      expect((error as OrganizationReconciliationProvenRuleError).code).toBe(code);
    }
  });

  it("rejects standalone auth_rule rows even when no item references them", () => {
    expect(() => calculateRuleFreeYiiRbacClosure({
      rules: ["orphanRule"],
      items: [{ name: "admin", type: "role", ruleName: null }],
      relations: []
    }, ["admin"])).toThrow(/auth_rule/);
  });

  it("rejects accessor-backed RBAC graphs without invoking them", () => {
    let invoked = false;
    const graph = { rules: [], relations: [] } as Record<string, unknown>;
    Object.defineProperty(graph, "items", {
      enumerable: true,
      get: () => {
        invoked = true;
        return [];
      }
    });
    expect(() => calculateRuleFreeYiiRbacClosure(graph, [])).toThrow(/accessor/);
    expect(invoked).toBe(false);
  });
});
