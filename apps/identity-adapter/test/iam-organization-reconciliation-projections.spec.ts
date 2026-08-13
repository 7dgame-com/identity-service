import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY,
  ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
  canonicalizeOrganizationReconciliationProjectionCatalog,
  organizationReconciliationProjectionCatalogDigest,
  organizationReconciliationProjectionReadiness,
  organizationRefForLegacyId,
  pluginRefForId,
  projectCampusContexts,
  projectEffectiveDecisions,
  projectOrganizationScopedRoles,
  projectPluginBindings,
  projectPluginVisibility,
  type OrganizationReconciliationPlugin,
  type OrganizationReconciliationProjectionInput
} from "../src/iam-organization-reconciliation-projections.js";
import {
  isCanonicalAuthorizationContext,
  isCanonicalOrganizationRef
} from "../src/iam-organization-reconciliation-refs.js";

describe("organization reconciliation authoritative projections", () => {
  it("keeps production catalogs fail-closed", () => {
    expect(ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY).toBe(false);
    expect(organizationReconciliationProjectionReadiness()).toEqual({
      ready: false,
      blockers: [
        "compiled-projection-catalog-missing",
        "identity-directory-read-model-incomplete",
        "identity-mapping-read-model-incomplete",
        "campus-catalog-not-owner-approved",
        "campus-platform-global-public-summary-not-owner-approved",
        "effective-capability-catalog-not-owner-approved",
        "exact-capability-context-execution-not-authorized",
        "projection-binding-not-integrated"
      ]
    });
  });

  it("uses stable ID-based organization and plugin refs", () => {
    expect(organizationRefForLegacyId(17)).toBe("legacy-org:17");
    expect(organizationRefForLegacyId("17")).toBe("legacy-org:17");
    expect(pluginRefForId("campus")).toBe("plugin:campus");
    expect(() => organizationRefForLegacyId("017")).toThrow(/invalid/);
    expect(() => pluginRefForId(" campus ")).toThrow(/canonical/);
    expect(() => pluginRefForId("campus tool")).toThrow(/canonical ID token/);
    expect(() => pluginRefForId("campus/tool")).toThrow(/canonical ID token/);
    expect(() => pluginRefForId("campus_tool")).toThrow(/canonical ID token/);
    expect(() => pluginRefForId("校园")).toThrow(/canonical ID token/);
    expect(() => pluginRefForId("a".repeat(65))).toThrow(/canonical ID token/);
    expect(() => pluginRefForId("plugin:campus")).toThrow(/namespace prefix/);
    expect(isCanonicalAuthorizationContext("organization", "legacy-org:17")).toBe(true);
    expect(isCanonicalAuthorizationContext("platform-global", "org:platform-global")).toBe(true);
    expect(isCanonicalAuthorizationContext("public", "org:public")).toBe(true);
    expect(isCanonicalAuthorizationContext("organization", "org:public")).toBe(false);
    expect(isCanonicalAuthorizationContext("public", "org:platform-global")).toBe(false);
    expect(isCanonicalAuthorizationContext("platform-global", "legacy-org:17")).toBe(false);
    expect(isCanonicalOrganizationRef("org:platform-global", true)).toBe(false);
  });

  it("projects only explicitly member-scoped roles and never expands root", () => {
    expect(projectOrganizationScopedRoles(input(), [
      { roleRef: "root", scope: "global" },
      { roleRef: "manager", scope: "member-organization" },
      { roleRef: "user", scope: "global" },
      { roleRef: "admin", scope: "member-organization" }
    ])).toEqual([
      {
        subjectRef: "legacy-user:2",
        legacyOrganizationId: 1,
        roleRef: "manager",
        active: true
      },
      {
        subjectRef: "legacy-user:4",
        legacyOrganizationId: 1,
        roleRef: "admin",
        active: true
      }
    ]);

    expect(() => projectOrganizationScopedRoles(input(), [
      { roleRef: "root", scope: "global" }
    ])).toThrow(/no reviewed organization-scope policy/);
    expect(() => projectOrganizationScopedRoles(input(), [
      { roleRef: "root", scope: "member-organization" },
      { roleRef: "manager", scope: "member-organization" },
      { roleRef: "user", scope: "global" },
      { roleRef: "admin", scope: "member-organization" }
    ])).toThrow(/root role must remain platform-global/);
  });

  it("resolves plugin binding names to stable organization refs and models SQL NULL as public", () => {
    expect(projectPluginBindings(input().organizations, plugins())).toEqual([
      {
        pluginRef: "plugin:campus",
        bindingRef: "plugin:campus:legacy-org:1",
        organizationRef: "legacy-org:1",
        active: true
      },
      {
        pluginRef: "plugin:disabled-tool",
        bindingRef: "plugin:disabled-tool:org:public",
        organizationRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
        active: false
      },
      {
        pluginRef: "plugin:public-tool",
        bindingRef: "plugin:public-tool:org:public",
        organizationRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF,
        active: true
      }
    ]);

    expect(() => projectPluginBindings(input().organizations, [
      { pluginId: "bad", enabled: true, accessScope: "auth-only", organizationName: "" }
    ])).toThrow(/canonical/);
    expect(() => projectPluginBindings(input().organizations, [
      { pluginId: "bad", enabled: true, accessScope: "auth-only", organizationName: "missing" }
    ])).toThrow(/unresolved/);
  });

  it("produces an explicit allow or deny for every subject and plugin", () => {
    const records = projectPluginVisibility(input(), plugins());
    expect(records).toHaveLength(12);
    expect(decision(records, "legacy-user:1", "plugin:campus")).toBe("allow");
    expect(decision(records, "legacy-user:2", "plugin:campus")).toBe("allow");
    expect(decision(records, "legacy-user:3", "plugin:campus")).toBe("deny");
    expect(decision(records, "legacy-user:3", "plugin:public-tool")).toBe("allow");
    expect(decision(records, "legacy-user:4", "plugin:public-tool")).toBe("deny");
    expect(records.filter((record) => record.pluginRef === "plugin:disabled-tool"))
      .toEqual(expect.arrayContaining([
        expect.objectContaining({ subjectRef: "legacy-user:1", decision: "deny" }),
        expect.objectContaining({ subjectRef: "legacy-user:2", decision: "deny" }),
        expect.objectContaining({ subjectRef: "legacy-user:3", decision: "deny" }),
        expect.objectContaining({ subjectRef: "legacy-user:4", decision: "deny" })
      ]));
  });

  it("projects campus context with root-global and manager/admin membership semantics", () => {
    const records = projectCampusContexts(input(), [
      { contextKind: "organization", contextRef: "legacy-org:1" },
      { contextKind: "organization", contextRef: "legacy-org:2" },
      { contextKind: "platform-global", contextRef: "org:platform-global" },
      { contextKind: "public", contextRef: "org:public" }
    ]);
    expect(records).toHaveLength(16);
    expect(campusDecision(records, "legacy-user:1", "legacy-org:1")).toBe("allow");
    expect(campusDecision(records, "legacy-user:1", "legacy-org:2")).toBe("allow");
    expect(campusDecision(records, "legacy-user:2", "legacy-org:1")).toBe("allow");
    expect(campusDecision(records, "legacy-user:2", "legacy-org:2")).toBe("deny");
    expect(campusDecision(records, "legacy-user:3", "legacy-org:2")).toBe("deny");
    expect(campusDecision(records, "legacy-user:4", "legacy-org:1")).toBe("deny");
    expect(campusDecision(records, "legacy-user:1", "org:platform-global")).toBe("deny");
    expect(campusDecision(records, "legacy-user:1", "org:public")).toBe("deny");
  });

  it("keeps the two reserved campus contexts when O=0", () => {
    const emptyOrganizations = { ...input(), organizations: [], memberships: [] };
    const records = projectCampusContexts(emptyOrganizations, [
      { contextKind: "platform-global", contextRef: "org:platform-global" },
      { contextKind: "public", contextRef: "org:public" }
    ]);
    expect(records).toHaveLength(emptyOrganizations.subjects.length * 2);
    expect(new Set(records.map((record) => `${record.contextKind}\u0000${record.contextRef}`)))
      .toEqual(new Set(["platform-global\u0000org:platform-global", "public\u0000org:public"]));
  });

  it("projects the structural subject x (organization + 2) x capability universe", () => {
    const records = projectEffectiveDecisions(input(), [
      {
        resourceRef: "organization-users",
        capabilityRef: "read",
        minimumRole: "user",
        membershipRequired: true,
        rootMayBypassMembership: true
      },
      {
        resourceRef: "organization-users",
        capabilityRef: "manage",
        minimumRole: "manager",
        membershipRequired: true,
        rootMayBypassMembership: true
      }
    ]);
    expect(records).toHaveLength(32);
    expect(effectiveDecision(records, "legacy-user:1", "legacy-org:2", "manage")).toBe("allow");
    expect(effectiveDecision(records, "legacy-user:2", "legacy-org:1", "manage")).toBe("allow");
    expect(effectiveDecision(records, "legacy-user:2", "legacy-org:2", "manage")).toBe("deny");
    expect(effectiveDecision(records, "legacy-user:3", "legacy-org:2", "read")).toBe("allow");
    expect(effectiveDecision(records, "legacy-user:3", "legacy-org:2", "manage")).toBe("deny");
    expect(effectiveDecision(records, "legacy-user:4", "legacy-org:1", "manage")).toBe("deny");
    expect(effectiveDecision(records, "legacy-user:1", "org:platform-global", "manage")).toBe("deny");
    expect(effectiveDecision(records, "legacy-user:1", "org:public", "manage")).toBe("deny");
  });

  it("rejects unknown references, duplicate active keys, and ambiguous names", () => {
    const unknownMembership = input();
    expect(() => projectPluginVisibility({
      ...unknownMembership,
      memberships: [
        ...unknownMembership.memberships,
        { subjectRef: "legacy-user:999", legacyOrganizationId: 1, active: true }
      ]
    }, plugins())).toThrow(/unknown subject/);

    expect(() => projectPluginVisibility({
      ...input(),
      memberships: [
        ...input().memberships,
        { subjectRef: "legacy-user:2", legacyOrganizationId: 1, active: true }
      ]
    }, plugins())).toThrow(/duplicate active membership/);

    expect(() => projectPluginBindings([
      ...input().organizations,
      { legacyOrganizationId: 9, name: "north", title: null, active: true }
    ], plugins())).toThrow(/ambiguous name/);
  });

  it("hashes catalogs canonically without accepting non-JSON values", () => {
    const canonicalDigest = organizationReconciliationProjectionCatalogDigest({ b: 2, a: [1, true] });
    expect(canonicalDigest).toBe(organizationReconciliationProjectionCatalogDigest({ a: [1, true], b: 2 }));
    expect(organizationReconciliationProjectionCatalogDigest({ b: 3, a: [1, true] }))
      .not.toBe(organizationReconciliationProjectionCatalogDigest({ a: [1, true], b: 2 }));
    expect(canonicalDigest).not.toBe(
      createHash("sha256").update('{"a":[1,true],"b":2}').digest("hex")
    );
    expect(() => organizationReconciliationProjectionCatalogDigest({ value: undefined })).toThrow(/canonical JSON/);
  });

  it("copies and freezes one exact catalog without invoking accessors or ignoring hidden state", () => {
    const mutable = { rules: [{ capability: "read" }] };
    const canonical = canonicalizeOrganizationReconciliationProjectionCatalog(mutable);
    mutable.rules[0]!.capability = "write";
    expect(canonical).toEqual({ rules: [{ capability: "read" }] });
    expect(Object.isFrozen(canonical)).toBe(true);
    expect(Object.isFrozen(canonical.rules)).toBe(true);
    expect(Object.isFrozen(canonical.rules[0])).toBe(true);

    let getterInvoked = false;
    const accessor = {} as Record<string, unknown>;
    Object.defineProperty(accessor, "minimumRole", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return "root";
      }
    });
    expect(() => organizationReconciliationProjectionCatalogDigest(accessor)).toThrow(/accessor/);
    expect(getterInvoked).toBe(false);

    const hidden = { minimumRole: "user" };
    Object.defineProperty(hidden, "membershipRequired", { enumerable: false, value: false });
    expect(() => organizationReconciliationProjectionCatalogDigest(hidden)).toThrow(/hidden/);
    expect(() => organizationReconciliationProjectionCatalogDigest({ [Symbol("scope")]: "root" }))
      .toThrow(/symbol/);
  });

  it("rejects subject refs outside the canonical Legacy user namespace", () => {
    expect(() => projectPluginVisibility({
      ...input(),
      subjects: [{ subjectRef: "private-user-1", active: true, authenticated: true }]
    }, plugins())).toThrow(/canonical Legacy user ref/);
  });
});

function input(): OrganizationReconciliationProjectionInput {
  return {
    subjects: [
      { subjectRef: "legacy-user:1", active: true, authenticated: true },
      { subjectRef: "legacy-user:2", active: true, authenticated: true },
      { subjectRef: "legacy-user:3", active: true, authenticated: true },
      { subjectRef: "legacy-user:4", active: false, authenticated: true }
    ],
    organizations: [
      { legacyOrganizationId: 1, name: "north", title: "North", active: true },
      { legacyOrganizationId: 2, name: "south", title: "South", active: true }
    ],
    memberships: [
      { subjectRef: "legacy-user:2", legacyOrganizationId: 1, active: true },
      { subjectRef: "legacy-user:3", legacyOrganizationId: 2, active: true },
      { subjectRef: "legacy-user:4", legacyOrganizationId: 1, active: true }
    ],
    roleAssignments: [
      { subjectRef: "legacy-user:1", roleRef: "root", active: true },
      { subjectRef: "legacy-user:2", roleRef: "manager", active: true },
      { subjectRef: "legacy-user:3", roleRef: "user", active: true },
      { subjectRef: "legacy-user:4", roleRef: "admin", active: true }
    ]
  };
}

function plugins(): OrganizationReconciliationPlugin[] {
  return [
    { pluginId: "public-tool", enabled: true, accessScope: "auth-only", organizationName: null },
    { pluginId: "campus", enabled: true, accessScope: "manager-only", organizationName: "north" },
    { pluginId: "disabled-tool", enabled: false, accessScope: "root-only", organizationName: null }
  ];
}

function decision(
  records: ReturnType<typeof projectPluginVisibility>,
  subjectRef: string,
  pluginRef: string
): string | undefined {
  return records.find((record) => record.subjectRef === subjectRef && record.pluginRef === pluginRef)?.decision;
}

function campusDecision(
  records: ReturnType<typeof projectCampusContexts>,
  subjectRef: string,
  contextRef: string
): string | undefined {
  return records.find((record) => record.subjectRef === subjectRef && record.contextRef === contextRef)?.decision;
}

function effectiveDecision(
  records: ReturnType<typeof projectEffectiveDecisions>,
  subjectRef: string,
  organizationRef: string,
  capabilityRef: string
): string | undefined {
  return records.find((record) =>
    record.subjectRef === subjectRef &&
    record.contextRef === organizationRef &&
    record.capabilityRef === capabilityRef
  )?.decision;
}
