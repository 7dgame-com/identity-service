import { createHash } from "node:crypto";
import {
  canonicalizeOrganizationReconciliationEvidenceValue,
  type OrganizationReconciliationEvidenceJsonValue
} from "./iam-organization-reconciliation-component-manifest.js";

export const ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT =
  "iam-organization-owner-semantic-registry/v1" as const;

export const ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES = Object.freeze({
  deterministicMappingContract: "legacy-organization-id-mapping/legacy-prefix-v1",
  legacySubjectLifecycleContract: "legacy-subject-lifecycle/status-10-active-v1",
  pluginBindingContract: "plugin-binding/sql-null-public-strict-v1",
  pluginAccessScopeContract: "plugin-access-scope/role-level-v1",
  yiiRbacContract: "yii-rbac/rule-free-closure-v1"
} as const);

export const ORGANIZATION_OWNER_DECISION_CONTRACTS = Object.freeze({
  identityShadowCandidateSelectors:
    "identity-organization-shadow-candidate-selectors-owner-decision/v2",
  roleScopes: "organization-role-scope-owner-decision/v2",
  pluginOverlay: "plugin-overlay-owner-decision/v1",
  campusPublicContext: "campus-public-context-owner-decision/v2",
  capabilityCatalog: "organization-capability-catalog-owner-decision/v2"
} as const);

export const ORGANIZATION_OWNER_DEVELOP_APPROVAL_CONTRACT =
  "iam-organization-owner-approval/xrteeth-develop/2026-08-11/v1" as const;

/**
 * User-approved Develop-only semantic choice. This is deliberately compiled
 * source, not an argv/environment/JSON switch. It approves the proposal-v2
 * recommendation only for the read-only xrteeth Develop reconciliation run.
 */
export const ORGANIZATION_OWNER_DEVELOP_APPROVAL = Object.freeze({
  contract: ORGANIZATION_OWNER_DEVELOP_APPROVAL_CONTRACT,
  environment: "xrteeth-develop",
  direction: "identity-native-replacement",
  selectors: "candidate-primary-shadow-diagnostic-no-union-or-fallback",
  roleScopes: "root-user-global-admin-manager-member-organization-comparison-only",
  pluginOverlay: "database-baseline-static-builtins-whole-object-override-authz-drift-block",
  campusContexts: "explicit-organization-platform-global-public-ambiguity-deny",
  capabilityEvaluator: "independent-rule-free-legacy-and-identity-graphs",
  userManagementEvaluator: "verified-root-and-live-yii-permission",
  unknownOrUnsupported: "P1-block",
  writesAuthorized: false,
  productionAuthorized: false
} as const);

export const ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256 = createHash("sha256")
  .update("iam-organization:owner-approval:xrteeth-develop:v1\u001f", "utf8")
  .update(JSON.stringify(ORGANIZATION_OWNER_DEVELOP_APPROVAL), "utf8")
  .digest("hex");

type DevelopCapabilitySurface = "campus" | "legacy-organization-api" | "user-management";
type DevelopCapabilityScope = "organization" | "platform-global" | "public";
type DevelopCapabilityDecisionRule =
  | "fixed-deny"
  | "verified-root-active-org"
  | "verified-root-or-active-member"
  | "plus-explicit-public-root"
  | "live-yii-rule-free-permission"
  | "verified-root-and-live-yii-permission";

interface DevelopCapabilityEntryInput {
  readonly surface: DevelopCapabilitySurface;
  readonly capabilityId: string;
  readonly resourceId: string;
  readonly actions: readonly string[];
  readonly permissionItems: readonly string[];
  readonly globalRoles: readonly string[];
  readonly organizationRoles: readonly string[];
  readonly scope: readonly DevelopCapabilityScope[];
  readonly decisionRule: DevelopCapabilityDecisionRule;
  readonly targetSpecificConstraints: "not-applicable" | "excluded-separate-evaluator";
}

function frozenStrings<const T extends readonly string[]>(values: T): T {
  return Object.freeze([...values]) as unknown as T;
}

function developCapabilityEntry(input: DevelopCapabilityEntryInput) {
  return Object.freeze({
    surface: input.surface,
    capabilityId: input.capabilityId,
    bindingState: "owner-bound" as const,
    resourceId: input.resourceId,
    actions: frozenStrings(input.actions),
    permissionItems: frozenStrings(input.permissionItems),
    roles: Object.freeze({
      global: frozenStrings(input.globalRoles),
      organization: frozenStrings(input.organizationRoles)
    }),
    scope: Object.freeze([...input.scope]),
    decisionRule: input.decisionRule,
    targetSpecificConstraints: input.targetSpecificConstraints
  });
}

const DEVELOP_CAMPUS_CAPABILITY_IDS = Object.freeze([
  "manage-classes",
  "manage-global-tools",
  "manage-school-boundaries",
  "manage-student-accounts",
  "view-classes",
  "view-dashboard",
  "view-schools",
  "view-students",
  "view-tools"
] as const);

/**
 * Exact owner-bound Develop catalog copied from the reviewed WP4 proposal.
 * This is compiled source: the proposal JSON is not read at runtime.
 */
export const ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS = Object.freeze({
  identityShadowCandidateSelectors: Object.freeze({
    primary: "candidate",
    organization: Object.freeze({ source: "legacy", status: "candidate" }),
    mapping: Object.freeze({ source: "legacy", status: "active" }),
    membership: Object.freeze({ source: "legacy", status: "candidate", explicitEmpty: true }),
    shadow: Object.freeze({ source: "legacy-shadow", status: "shadow", use: "diagnostic-only" }),
    iam: Object.freeze({ source: "legacy-import-candidate", status: "candidate", exactChecksum: true }),
    union: "prohibited",
    fallback: "prohibited"
  }),
  roleScopes: Object.freeze({
    globalOnly: Object.freeze(["root", "user"]),
    memberOrganization: Object.freeze(["admin", "manager"]),
    rootExpansion: "prohibited",
    projectionAuthority: "comparison-only",
    unknownRole: "P1-block"
  }),
  pluginOverlay: Object.freeze({
    contract: ORGANIZATION_OWNER_DECISION_CONTRACTS.pluginOverlay,
    decisionState: "owner-bound",
    databaseDatasetId: "plugin-registry",
    staticArtifact: Object.freeze({
      path: "web/public/config/plugins.json",
      sha256: "724bcb509672a0f2266a5748f08b71d52b099f7e636098c8573eaa115878bf8c",
      evidenceBoundary: "source-tree-proposal-not-deployment-proof"
    }),
    staticBuiltIns: Object.freeze([
      Object.freeze({
        id: "system-admin",
        enabled: true,
        accessScope: "root-only",
        organizationName: null
      }),
      Object.freeze({
        id: "user-management",
        enabled: true,
        accessScope: "root-only",
        organizationName: null
      })
    ]),
    mergePolicy: Object.freeze({
      baseline: "api-database",
      sameId: "local-whole-object-overrides-database",
      newLocalId: "append-after-database",
      version: "local-non-empty-first"
    }),
    requiredAuthorizationFields: Object.freeze([
      "id", "enabled", "accessScope", "organizationName"
    ] as const),
    missingAuthorizationField: "fail-closed",
    collisionAuthorizationDrift: "P1-and-block",
    unknownPlugin: "P1-and-block",
    deploymentArtifactDigest: "required-separate-runtime-evidence"
  }),
  campusPublicContext: Object.freeze({
    contract: ORGANIZATION_OWNER_DECISION_CONTRACTS.campusPublicContext,
    decisionState: "owner-bound",
    executionState: "owner-bound-campus-context-decision-execution",
    canonicalMarkers: Object.freeze({
      platformGlobal: "org:platform-global",
      public: "org:public"
    }),
    reservedOrganizationSlugs: Object.freeze(["platform-global", "public"] as const),
    contextClassifier: Object.freeze({
      state: "owner-bound",
      contextKinds: Object.freeze(["organization", "platform-global", "public"] as const),
      recommended: Object.freeze({
        organization: "verified-positive-id-or-unambiguous-canonical-slug",
        platformGlobal: "explicit-platform-global-marker-only",
        public: "explicit-public-marker-only",
        overlapOrAmbiguity: "deny"
      })
    }),
    organizationMatch: Object.freeze({
      positiveId: "exact-id-first-and-exclusive",
      slugFallback: "only-when-both-ids-absent-exact-canonical-lowercase",
      idNameConflict: "deny",
      ambiguousOrEmptyName: "deny"
    }),
    decisionClasses: Object.freeze({
      "fixed-deny": Object.freeze({
        organization: "deny",
        "platform-global": "deny",
        public: "deny"
      }),
      "verified-root-active-org": Object.freeze({
        organization: "verified-root-and-active-organization",
        "platform-global": "deny",
        public: "deny"
      }),
      "verified-root-or-active-member": Object.freeze({
        organization: "verified-root-or-active-member-admin-manager",
        "platform-global": "deny",
        public: "deny"
      }),
      "plus-explicit-public-root": Object.freeze({
        organization: "verified-root-or-active-member-admin-manager",
        "platform-global": "deny",
        public: "verified-root-only"
      })
    }),
    capabilityRules: Object.freeze([
      Object.freeze({ capabilityId: "manage-classes", bindingState: "owner-bound", decisionClass: "fixed-deny" }),
      Object.freeze({ capabilityId: "manage-global-tools", bindingState: "owner-bound", decisionClass: "verified-root-active-org" }),
      Object.freeze({ capabilityId: "manage-school-boundaries", bindingState: "owner-bound", decisionClass: "verified-root-or-active-member" }),
      Object.freeze({ capabilityId: "manage-student-accounts", bindingState: "owner-bound", decisionClass: "plus-explicit-public-root" }),
      Object.freeze({ capabilityId: "view-classes", bindingState: "owner-bound", decisionClass: "fixed-deny" }),
      Object.freeze({ capabilityId: "view-dashboard", bindingState: "owner-bound", decisionClass: "verified-root-or-active-member" }),
      Object.freeze({ capabilityId: "view-schools", bindingState: "owner-bound", decisionClass: "verified-root-or-active-member" }),
      Object.freeze({ capabilityId: "view-students", bindingState: "owner-bound", decisionClass: "plus-explicit-public-root" }),
      Object.freeze({ capabilityId: "view-tools", bindingState: "owner-bound", decisionClass: "verified-root-or-active-member" })
    ]),
    summaryRule: Object.freeze({
      evaluator: "any-exact-campus-capability-allow",
      requiredCapabilityIds: DEVELOP_CAMPUS_CAPABILITY_IDS,
      missingCapability: "P1-block"
    }),
    failurePolicy: Object.freeze({
      unknownContext: "P1-block",
      overlappingContext: "P1-block",
      missingGlobalPolicy: "P1-block",
      missingMembership: "deny"
    })
  }),
  capabilityCatalog: Object.freeze({
    contract: ORGANIZATION_OWNER_DECISION_CONTRACTS.capabilityCatalog,
    decisionState: "owner-bound",
    executionState: "owner-bound-context-decision-execution",
    entries: Object.freeze([
      developCapabilityEntry({
        surface: "campus", capabilityId: "manage-classes", resourceId: "campus.classes",
        actions: ["manage"], permissionItems: [], globalRoles: [], organizationRoles: [],
        scope: ["organization", "platform-global", "public"], decisionRule: "fixed-deny",
        targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "manage-global-tools", resourceId: "campus.tools",
        actions: ["manage-global"], permissionItems: [], globalRoles: ["root"], organizationRoles: [],
        scope: ["organization"], decisionRule: "verified-root-active-org",
        targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "manage-school-boundaries", resourceId: "campus.schools",
        actions: ["manage-boundaries"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization"],
        decisionRule: "verified-root-or-active-member", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "manage-student-accounts", resourceId: "campus.students",
        actions: ["manage-accounts"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization", "public"],
        decisionRule: "plus-explicit-public-root", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "view-classes", resourceId: "campus.classes",
        actions: ["view"], permissionItems: [], globalRoles: [], organizationRoles: [],
        scope: ["organization", "platform-global", "public"], decisionRule: "fixed-deny",
        targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "view-dashboard", resourceId: "campus.dashboard",
        actions: ["view"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization"],
        decisionRule: "verified-root-or-active-member", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "view-schools", resourceId: "campus.schools",
        actions: ["view"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization"],
        decisionRule: "verified-root-or-active-member", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "view-students", resourceId: "campus.students",
        actions: ["view"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization", "public"],
        decisionRule: "plus-explicit-public-root", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "campus", capabilityId: "view-tools", resourceId: "campus.tools",
        actions: ["view"], permissionItems: [], globalRoles: ["root"],
        organizationRoles: ["admin", "manager"], scope: ["organization"],
        decisionRule: "verified-root-or-active-member", targetSpecificConstraints: "not-applicable"
      }),
      developCapabilityEntry({
        surface: "legacy-organization-api", capabilityId: "organization.bind-user", resourceId: "organization",
        actions: ["bind-user"], permissionItems: ["organization.bind-user"], globalRoles: [],
        organizationRoles: [], scope: ["platform-global"], decisionRule: "live-yii-rule-free-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "legacy-organization-api", capabilityId: "organization.create", resourceId: "organization",
        actions: ["create"], permissionItems: ["organization.create"], globalRoles: [],
        organizationRoles: [], scope: ["platform-global"], decisionRule: "live-yii-rule-free-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "legacy-organization-api", capabilityId: "organization.list", resourceId: "organization",
        actions: ["list"], permissionItems: ["organization.list"], globalRoles: [],
        organizationRoles: [], scope: ["platform-global"], decisionRule: "live-yii-rule-free-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "legacy-organization-api", capabilityId: "organization.update", resourceId: "organization",
        actions: ["update"], permissionItems: ["organization.update"], globalRoles: [],
        organizationRoles: [], scope: ["platform-global"], decisionRule: "live-yii-rule-free-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "change-role", resourceId: "user-management.user-role",
        actions: ["change"], permissionItems: ["user-management.change-role"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "create-user", resourceId: "user-management.user",
        actions: ["create"], permissionItems: ["user-management.create-user"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "delete-user", resourceId: "user-management.user",
        actions: ["delete"], permissionItems: ["user-management.delete-user"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "list-users", resourceId: "user-management.user",
        actions: ["list"], permissionItems: ["user-management.list-users"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "manage-invitations", resourceId: "user-management.invitation",
        actions: ["manage"], permissionItems: ["user-management.manage-invitations"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "update-user", resourceId: "user-management.user",
        actions: ["update"], permissionItems: ["user-management.update-user"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      }),
      developCapabilityEntry({
        surface: "user-management", capabilityId: "view-user", resourceId: "user-management.user",
        actions: ["view"], permissionItems: ["user-management.view-user"], globalRoles: ["root"],
        organizationRoles: [], scope: ["platform-global"],
        decisionRule: "verified-root-and-live-yii-permission",
        targetSpecificConstraints: "excluded-separate-evaluator"
      })
    ]),
    legacyEvaluator: Object.freeze({
      state: "owner-bound",
      assignmentDatasetId: "legacy-rbac-assignment",
      itemDatasetId: "legacy-rbac-item",
      edgeDatasetId: "legacy-rbac-edge",
      snapshotBinding: "live-pinned-repeatable-read",
      directAssignments: "roles-and-permissions",
      nestedPermissions: "parent-to-child-transitive-closure",
      namedRule: "P1-block",
      unknownAssignment: "P1-block",
      cycle: "P1-block",
      hardcodedPrivilegedRoles: "prohibited"
    }),
    identityEvaluator: Object.freeze({
      state: "owner-bound",
      policyVersionDatasetId: "identity-iam-policy-version",
      roleDatasetId: "identity-iam-role",
      permissionDatasetId: "identity-iam-permission",
      edgeDatasetId: "identity-iam-item-relation",
      assignmentDatasetId: "identity-iam-subject-assignment",
      assignmentSnapshotDatasetId: "identity-iam-subject-assignment-snapshot",
      policyChecksumBinding: "exact-compiled-checksum-only",
      directAssignments: "roles-and-permissions",
      nestedPermissions: "parent-to-child-transitive-closure",
      unknownAssignment: "P1-block",
      missingAssignment: "P1-block",
      cycle: "P1-block",
      duplicate: "P1-block",
      namedRule: "P1-block",
      fallback: "prohibited"
    }),
    userManagementEvaluatorChoice: Object.freeze({
      state: "owner-bound",
      recommended: "frontend-verified-root-and-backend-live-yii-permission",
      alternative: "backend-live-yii-permission-only",
      targetSpecificConstraints: "excluded-require-separate-evaluator"
    }),
    unbindContract: "organization.bind-user",
    manageOrganizationsContract: "live-yii-permission-no-hardcoded-root-admin",
    pluginVisibility: "separate-surface-not-general-capability",
    roleLevelApproximation: "prohibited",
    unknownCapability: "fail-closed-owner-review-required",
    externalCallerCompleteness: "not-claimed"
  })
} as const);

function decisionCatalogSha256(name: OrganizationOwnerDecisionName, catalog: unknown): string {
  return createHash("sha256")
    .update(`iam-organization:owner-decision-catalog:${name}:v1\u001f`, "utf8")
    .update(JSON.stringify(catalog), "utf8")
    .digest("hex");
}

export type OrganizationOwnerDecisionName = keyof typeof ORGANIZATION_OWNER_DECISION_CONTRACTS;

/**
 * Independently reviewed literal pins. These values are deliberately not
 * derived from ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS at runtime.
 */
export const ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256 = Object.freeze({
  identityShadowCandidateSelectors: "e3ed89538a845200bb4dcfdcea113f1d940cd5a802b865929bad9f63933117a8",
  roleScopes: "0ebfed46d3699c2c508a5f49fa91da5b5c963afb8048d7639ec577abc720bfff",
  pluginOverlay: "753e82c0a84e820d279a309f9f23fb99987c26ac7072c09ba0cb23eccc28fadd",
  campusPublicContext: "51280ce6bf0b1e54118011eac9bb5c08068eaef38d8042ce6fd2db44587a3347",
  capabilityCatalog: "19357bafa8d4cfbb2070b8f33bcb8bbcb820c7efbe9e40b8f13ce3435ac88d97"
} satisfies Readonly<Record<OrganizationOwnerDecisionName, string>>);

export interface OrganizationOwnerSemanticDecisionPin {
  readonly decisionContract: (typeof ORGANIZATION_OWNER_DECISION_CONTRACTS)[OrganizationOwnerDecisionName];
  readonly approvalSha256: string;
  readonly catalogSha256: string;
}

export interface OrganizationOwnerSemanticRegistryInput {
  readonly contract: typeof ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT;
  readonly registryId: string;
  readonly registryRevisionSha256: string;
  readonly primitives: typeof ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES;
  readonly ownerDecisions: Readonly<{
    identityShadowCandidateSelectors: OrganizationOwnerSemanticDecisionPin | null;
    roleScopes: OrganizationOwnerSemanticDecisionPin | null;
    pluginOverlay: OrganizationOwnerSemanticDecisionPin | null;
    campusPublicContext: OrganizationOwnerSemanticDecisionPin | null;
    capabilityCatalog: OrganizationOwnerSemanticDecisionPin | null;
  }>;
}

export const ORGANIZATION_OWNER_DEVELOP_DECISION_PINS = Object.freeze({
  identityShadowCandidateSelectors: Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS.identityShadowCandidateSelectors,
    approvalSha256: ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
    catalogSha256: ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256.identityShadowCandidateSelectors
  }),
  roleScopes: Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS.roleScopes,
    approvalSha256: ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
    catalogSha256: ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256.roleScopes
  }),
  pluginOverlay: Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS.pluginOverlay,
    approvalSha256: ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
    catalogSha256: ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256.pluginOverlay
  }),
  campusPublicContext: Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS.campusPublicContext,
    approvalSha256: ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
    catalogSha256: ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256.campusPublicContext
  }),
  capabilityCatalog: Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS.capabilityCatalog,
    approvalSha256: ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256,
    catalogSha256: ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256.capabilityCatalog
  })
} satisfies OrganizationOwnerSemanticRegistryInput["ownerDecisions"]);

export interface CanonicalOrganizationOwnerSemanticRegistry
  extends OrganizationOwnerSemanticRegistryInput {
  readonly registrySha256: string;
}

export type OrganizationOwnerSemanticRegistryBlocker =
  | "compiled-owner-semantic-registry-empty"
  | "identity-shadow-candidate-selectors-owner-decision-missing"
  | "role-scope-owner-decision-missing"
  | "plugin-overlay-owner-decision-missing"
  | "campus-public-context-owner-decision-missing"
  | "capability-catalog-owner-decision-missing";

export interface OrganizationOwnerSemanticRegistryReadiness {
  readonly ready: false;
  readonly compiledRegistryCount: 0;
  readonly blockers: readonly OrganizationOwnerSemanticRegistryBlocker[];
}

const REGISTRY_DIGEST_DOMAIN = Buffer.from(
  "iam-organization:owner-semantic-registry:v1\u001f",
  "utf8"
);

/**
 * Deliberately empty production registry. This table may only be populated by
 * a reviewed source change. No argv, environment, JSON file, request body, or
 * evidence envelope is consulted by production lookup/readiness.
 */
const COMPILED_OWNER_SEMANTIC_REGISTRY: readonly CanonicalOrganizationOwnerSemanticRegistry[] =
  Object.freeze([]);

const REQUIRED_PRIMITIVE_KEYS = Object.freeze(Object.keys(ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES).sort());
const REQUIRED_DECISION_KEYS = Object.freeze(Object.keys(ORGANIZATION_OWNER_DECISION_CONTRACTS).sort());

export class OrganizationOwnerSemanticRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OrganizationOwnerSemanticRegistryError";
  }
}

const REVIEWED_DEVELOP_DECISION_NAMES = Object.freeze([
  "identityShadowCandidateSelectors",
  "roleScopes",
  "pluginOverlay",
  "campusPublicContext",
  "capabilityCatalog"
] as const satisfies readonly OrganizationOwnerDecisionName[]);

/**
 * Verifies a literal catalog set against independently reviewed pins. This is
 * also invoked during module initialization, before the Develop candidate is
 * constructed, so catalog drift cannot silently repin itself.
 */
export function assertOrganizationOwnerDevelopDecisionCatalogReviewPins(
  catalogs: unknown
): void {
  if (catalogs === null || typeof catalogs !== "object" || Array.isArray(catalogs)) {
    throw new OrganizationOwnerSemanticRegistryError(
      "The reviewed Develop decision catalog set is invalid."
    );
  }
  const record = catalogs as Readonly<Record<string, unknown>>;
  const actualNames = Object.keys(record).sort();
  const expectedNames = [...REVIEWED_DEVELOP_DECISION_NAMES].sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    throw new OrganizationOwnerSemanticRegistryError(
      "The reviewed Develop decision catalog set has missing or unknown catalogs."
    );
  }
  for (const name of REVIEWED_DEVELOP_DECISION_NAMES) {
    const actualSha256 = decisionCatalogSha256(name, record[name]);
    const expectedSha256 = ORGANIZATION_OWNER_DEVELOP_REVIEWED_CATALOG_SHA256[name];
    if (actualSha256 !== expectedSha256) {
      throw new OrganizationOwnerSemanticRegistryError(
        `The Develop ${name} decision catalog does not match its independently reviewed literal SHA-256.`
      );
    }
  }
}

assertOrganizationOwnerDevelopDecisionCatalogReviewPins(
  ORGANIZATION_OWNER_DEVELOP_DECISION_CATALOGS
);

/**
 * Strictly validates an owner-semantic registry candidate and returns a
 * detached, deeply frozen canonical copy. Validation does not provision the
 * candidate into the compiled production registry.
 */
export function canonicalizeOrganizationOwnerSemanticRegistry(
  candidate: unknown
): CanonicalOrganizationOwnerSemanticRegistry {
  const canonical = canonicalizeOrganizationReconciliationEvidenceValue(candidate);
  requireExactKeys(canonical, [
    "contract",
    "registryId",
    "registryRevisionSha256",
    "primitives",
    "ownerDecisions"
  ], "owner semantic registry");
  const registry = canonical as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (registry.contract !== ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT) {
    throw new OrganizationOwnerSemanticRegistryError("The owner semantic registry contract is invalid.");
  }
  const registryId = requireRegistryId(registry.registryId);
  const registryRevisionSha256 = requireSha256(
    registry.registryRevisionSha256,
    "registry revision"
  );
  const primitives = validatePrimitives(registry.primitives);
  const ownerDecisions = validateOwnerDecisions(registry.ownerDecisions);
  const unsigned = Object.freeze({
    contract: ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT,
    registryId,
    registryRevisionSha256,
    primitives,
    ownerDecisions
  });
  return Object.freeze({
    ...unsigned,
    registrySha256: createRegistryDigest(unsigned)
  });
}

const ORGANIZATION_OWNER_DEVELOP_REGISTRY_REVISION_SHA256 = createHash("sha256")
  .update("iam-organization:owner-semantic-registry-revision:xrteeth-develop:v1\u001f", "utf8")
  .update(ORGANIZATION_OWNER_DEVELOP_APPROVAL_SHA256, "utf8")
  .update(JSON.stringify(ORGANIZATION_OWNER_DEVELOP_DECISION_PINS), "utf8")
  .digest("hex");

/**
 * Fully populated, user-approved Develop candidate. It remains outside the
 * production registry until source attestation, projectors, operation
 * evidence, external provenance and the runtime pipeline are atomically
 * registered. Callers cannot promote it by passing its digest.
 */
export const ORGANIZATION_OWNER_DEVELOP_APPROVED_REGISTRY_CANDIDATE =
  canonicalizeOrganizationOwnerSemanticRegistry({
    contract: ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT,
    registryId: "xrteeth-develop/identity-native-replacement/2026-08-11",
    registryRevisionSha256: ORGANIZATION_OWNER_DEVELOP_REGISTRY_REVISION_SHA256,
    primitives: ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES,
    ownerDecisions: ORGANIZATION_OWNER_DEVELOP_DECISION_PINS
  });

/** Returns missing owner decisions for a validated candidate; it never confers production trust. */
export function organizationOwnerSemanticRegistryCandidateBlockers(
  registry: CanonicalOrganizationOwnerSemanticRegistry
): readonly OrganizationOwnerSemanticRegistryBlocker[] {
  const blockers: OrganizationOwnerSemanticRegistryBlocker[] = [];
  if (registry.ownerDecisions.identityShadowCandidateSelectors === null) {
    blockers.push("identity-shadow-candidate-selectors-owner-decision-missing");
  }
  if (registry.ownerDecisions.roleScopes === null) {
    blockers.push("role-scope-owner-decision-missing");
  }
  if (registry.ownerDecisions.pluginOverlay === null) {
    blockers.push("plugin-overlay-owner-decision-missing");
  }
  if (registry.ownerDecisions.campusPublicContext === null) {
    blockers.push("campus-public-context-owner-decision-missing");
  }
  if (registry.ownerDecisions.capabilityCatalog === null) {
    blockers.push("capability-catalog-owner-decision-missing");
  }
  return Object.freeze(blockers);
}

export function organizationOwnerSemanticRegistryReadiness(): OrganizationOwnerSemanticRegistryReadiness {
  return Object.freeze({
    ready: false,
    compiledRegistryCount: 0,
    blockers: Object.freeze([
      "compiled-owner-semantic-registry-empty",
      "identity-shadow-candidate-selectors-owner-decision-missing",
      "role-scope-owner-decision-missing",
      "plugin-overlay-owner-decision-missing",
      "campus-public-context-owner-decision-missing",
      "capability-catalog-owner-decision-missing"
    ] as const)
  });
}

/** Production lookup can only return values compiled into this module. */
export function findCompiledOrganizationOwnerSemanticRegistry(
  registrySha256: string
): CanonicalOrganizationOwnerSemanticRegistry | undefined {
  if (!/^[a-f0-9]{64}$/.test(registrySha256)) return undefined;
  return COMPILED_OWNER_SEMANTIC_REGISTRY.find(
    (registry) => registry.registrySha256 === registrySha256
  );
}

function validatePrimitives(
  candidate: OrganizationReconciliationEvidenceJsonValue
): typeof ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES {
  requireExactKeys(candidate, REQUIRED_PRIMITIVE_KEYS, "owner semantic primitives");
  const primitives = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  for (const [name, expected] of Object.entries(ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES)) {
    if (primitives[name] !== expected) {
      throw new OrganizationOwnerSemanticRegistryError(
        `The proven semantic primitive ${name} cannot be overridden.`
      );
    }
  }
  return ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES;
}

function validateOwnerDecisions(
  candidate: OrganizationReconciliationEvidenceJsonValue
): OrganizationOwnerSemanticRegistryInput["ownerDecisions"] {
  requireExactKeys(candidate, REQUIRED_DECISION_KEYS, "owner semantic decisions");
  const decisions = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  return Object.freeze({
    identityShadowCandidateSelectors: validateDecisionPin(
      "identityShadowCandidateSelectors",
      decisions.identityShadowCandidateSelectors
    ),
    roleScopes: validateDecisionPin("roleScopes", decisions.roleScopes),
    pluginOverlay: validateDecisionPin("pluginOverlay", decisions.pluginOverlay),
    campusPublicContext: validateDecisionPin("campusPublicContext", decisions.campusPublicContext),
    capabilityCatalog: validateDecisionPin("capabilityCatalog", decisions.capabilityCatalog)
  });
}

function validateDecisionPin(
  name: OrganizationOwnerDecisionName,
  candidate: OrganizationReconciliationEvidenceJsonValue
): OrganizationOwnerSemanticDecisionPin | null {
  if (candidate === null) return null;
  requireExactKeys(candidate, ["decisionContract", "approvalSha256", "catalogSha256"], `${name} decision pin`);
  const pin = candidate as Record<string, OrganizationReconciliationEvidenceJsonValue>;
  if (pin.decisionContract !== ORGANIZATION_OWNER_DECISION_CONTRACTS[name]) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${name} decision contract is invalid.`);
  }
  return Object.freeze({
    decisionContract: ORGANIZATION_OWNER_DECISION_CONTRACTS[name],
    approvalSha256: requireSha256(pin.approvalSha256, `${name} approval`),
    catalogSha256: requireSha256(pin.catalogSha256, `${name} catalog`)
  });
}

function createRegistryDigest(input: OrganizationOwnerSemanticRegistryInput): string {
  return createHash("sha256")
    .update(REGISTRY_DIGEST_DOMAIN)
    .update(JSON.stringify(input), "utf8")
    .digest("hex");
}

function requireRegistryId(value: OrganizationReconciliationEvidenceJsonValue): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9][a-z0-9./:-]{0,127}$/.test(value) ||
    value.includes("..")
  ) {
    throw new OrganizationOwnerSemanticRegistryError("The owner semantic registry ID is invalid.");
  }
  return value;
}

function requireSha256(
  value: OrganizationReconciliationEvidenceJsonValue,
  label: string
): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${label} must be a full SHA-256 digest.`);
  }
  return value;
}

function requireExactKeys(
  value: OrganizationReconciliationEvidenceJsonValue,
  expectedKeys: readonly string[],
  label: string
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new OrganizationOwnerSemanticRegistryError(`The ${label} is invalid.`);
  }
  const actualKeys = Object.keys(value).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify([...expectedKeys].sort())) {
    throw new OrganizationOwnerSemanticRegistryError(
      `The ${label} has missing or unknown fields.`
    );
  }
}
