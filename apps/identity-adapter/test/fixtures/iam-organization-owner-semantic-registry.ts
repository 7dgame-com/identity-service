import {
  ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES,
  ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT,
  type OrganizationOwnerSemanticRegistryInput
} from "../../src/iam-organization-owner-semantic-registry.js";

/**
 * Test-only reviewed foundation fixture. Missing owner decisions are
 * intentional and must remain null; this fixture cannot provision production.
 */
export function reviewedTestOrganizationOwnerSemanticRegistryInput(): OrganizationOwnerSemanticRegistryInput {
  return {
    contract: ORGANIZATION_OWNER_SEMANTIC_REGISTRY_CONTRACT,
    registryId: "test/wp4/foundation-only",
    registryRevisionSha256: "1".repeat(64),
    primitives: { ...ORGANIZATION_OWNER_SEMANTIC_PRIMITIVES },
    ownerDecisions: {
      identityShadowCandidateSelectors: null,
      roleScopes: null,
      pluginOverlay: null,
      campusPublicContext: null,
      capabilityCatalog: null
    }
  };
}
