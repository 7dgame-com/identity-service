import type { OrganizationReconciliationTrustedProfile } from "./iam-organization-reconciliation-provenance.js";

/**
 * Production trust roots for organization reconciliation.
 *
 * This registry is intentionally empty. Provisioning a profile requires a
 * reviewed source change and a release; runtime arguments, environment,
 * evidence, attestations, and policy files must never supply or override pins.
 * Never commit private keys or PEM material here. A future entry contains only
 * an approved policy digest, expected environment, and public collector/node/
 * key identifiers plus public-key fingerprints.
 *
 * A released CLI artifact may provision exactly one profile. The explicit
 * --trust-profile argument must match it; zero or multiple compiled entries
 * fail closed so a caller cannot choose a weaker environment profile.
 */
const COMPILED_TRUST_PROFILES: Readonly<Record<string, OrganizationReconciliationTrustedProfile>> =
  Object.freeze({});

const TRUST_PROFILE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function resolveCompiledOrganizationReconciliationTrustProfile(
  profileId: string
): OrganizationReconciliationTrustedProfile | undefined {
  if (!TRUST_PROFILE_ID.test(profileId)) return undefined;
  const compiledProfileIds = Object.keys(COMPILED_TRUST_PROFILES);
  if (compiledProfileIds.length !== 1 || compiledProfileIds[0] !== profileId) return undefined;
  if (!Object.hasOwn(COMPILED_TRUST_PROFILES, profileId)) return undefined;
  const profile = COMPILED_TRUST_PROFILES[profileId];
  if (!profile || !compiledProfileIsValid(profileId, profile)) return undefined;
  return {
    ...profile,
    requiredCollectors: profile.requiredCollectors.map((collector) => ({ ...collector }))
  };
}

export const compiledOrganizationReconciliationTrustProfileCount =
  Object.keys(COMPILED_TRUST_PROFILES).length;

function compiledProfileIsValid(
  profileId: string,
  profile: OrganizationReconciliationTrustedProfile
): boolean {
  if (
    profile.profileId !== profileId ||
    !/^[a-f0-9]{64}$/.test(profile.policySha256) ||
    !TRUST_PROFILE_ID.test(profile.expectedEnvironment) ||
    profile.requiredCollectors.length < 2 ||
    profile.requiredCollectors.length > 8
  ) return false;
  const collectorIds = new Set<string>();
  const nodeIds = new Set<string>();
  const keyIds = new Set<string>();
  const fingerprints = new Set<string>();
  for (const collector of profile.requiredCollectors) {
    if (
      !TRUST_PROFILE_ID.test(collector.collectorId) ||
      !TRUST_PROFILE_ID.test(collector.nodeId) ||
      !TRUST_PROFILE_ID.test(collector.keyId) ||
      !/^[a-f0-9]{40}$/.test(collector.buildRevision) ||
      !/^[a-f0-9]{64}$/.test(collector.publicKeySha256) ||
      collectorIds.has(collector.collectorId) ||
      nodeIds.has(collector.nodeId) ||
      keyIds.has(collector.keyId) ||
      fingerprints.has(collector.publicKeySha256)
    ) return false;
    collectorIds.add(collector.collectorId);
    nodeIds.add(collector.nodeId);
    keyIds.add(collector.keyId);
    fingerprints.add(collector.publicKeySha256);
  }
  return true;
}
