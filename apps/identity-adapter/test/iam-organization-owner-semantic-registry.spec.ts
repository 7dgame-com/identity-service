import { describe, expect, it } from "vitest";
import {
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
