import { createHash, createPublicKey } from "node:crypto";
import { isProxy } from "node:util/types";
import {
  createOrganizationReconciliationTrustPolicySha256,
  parseOrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustPolicy,
  type OrganizationReconciliationTrustedCollector,
  type OrganizationReconciliationTrustedProfile
} from "./iam-organization-reconciliation-provenance.js";
import {
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION
} from "./generated/iam-organization-reconciliation-compiled-revision.js";

/**
 * Production trust roots for organization reconciliation.
 *
 * This template registry is intentionally empty. Provisioning a profile requires a
 * reviewed source change and a release; runtime arguments, environment,
 * evidence, attestations, and policy files must never supply or override pins.
 * Never commit private keys or private-key PEM material here. A future entry
 * contains only canonical public Ed25519 SPKI material and excludes
 * buildRevision. Its exact public policy and trusted-profile pins are both
 * derived from the container-compiled revision, so they cannot drift or pin a
 * caller-supplied/previous revision.
 *
 * A released CLI artifact may provision exactly one profile. Zero or multiple
 * compiled entries fail closed so a caller cannot select a weaker profile.
 */
export type OrganizationReconciliationTrustedCollectorTemplate =
  Omit<OrganizationReconciliationTrustedCollector, "buildRevision">;

export interface OrganizationReconciliationTrustPolicyTemplate
  extends Omit<OrganizationReconciliationTrustPolicy, "requiredCollectors"> {
  readonly requiredCollectors: readonly OrganizationReconciliationTrustedCollectorTemplate[];
}

export interface OrganizationReconciliationCompiledTrustBinding {
  readonly policy: OrganizationReconciliationTrustPolicy;
  readonly profile: OrganizationReconciliationTrustedProfile;
}

export type OrganizationReconciliationCompiledTrustBindingRegistry =
  Readonly<Record<string, OrganizationReconciliationCompiledTrustBinding>>;

const COMPILED_TRUST_PROFILE_TEMPLATES:
Readonly<Record<string, OrganizationReconciliationTrustPolicyTemplate>> =
  Object.freeze({});

const TRUST_PROFILE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FULL_BUILD_REVISION = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

const COMPILED_TRUST_BINDINGS = compileOrganizationReconciliationTrustPolicyTemplates(
  COMPILED_TRUST_PROFILE_TEMPLATES,
  ORGANIZATION_RECONCILIATION_COMPILED_BUILD_REVISION
);

export function resolveCompiledOrganizationReconciliationTrustProfile(
  profileId: string
): OrganizationReconciliationTrustedProfile | undefined {
  const binding = resolveCompiledBinding(profileId);
  return binding ? cloneFrozenProfile(binding.profile) : undefined;
}

/** Returns the exact public policy compiled from the same template/revision as the profile pin. */
export function resolveCompiledOrganizationReconciliationTrustPolicy(
  profileId: string
): OrganizationReconciliationTrustPolicy | undefined {
  const binding = resolveCompiledBinding(profileId);
  return binding ? cloneFrozenPolicy(binding.policy) : undefined;
}

/** Production-only zero/one selection used by the public-policy emitter. */
export function resolveSoleCompiledOrganizationReconciliationTrustBinding():
OrganizationReconciliationCompiledTrustBinding | undefined {
  const binding = selectSoleOrganizationReconciliationCompiledTrustBinding(COMPILED_TRUST_BINDINGS);
  return binding ? cloneFrozenBinding(binding) : undefined;
}

export const compiledOrganizationReconciliationTrustProfileCount =
  Object.keys(COMPILED_TRUST_BINDINGS).length;

/**
 * Pure compiler for a reviewed, revision-independent template registry.
 * It is exported so isolated fixtures can prove the production derivation. It
 * does not mutate or provision the production registry.
 */
export function compileOrganizationReconciliationTrustPolicyTemplates(
  templates: Readonly<Record<string, OrganizationReconciliationTrustPolicyTemplate>>,
  buildRevision: string | null
): OrganizationReconciliationCompiledTrustBindingRegistry {
  const empty = (): OrganizationReconciliationCompiledTrustBindingRegistry => Object.freeze({});
  if (!FULL_BUILD_REVISION.test(buildRevision ?? "")) return empty();
  try {
    assertPlainDataTree(templates, new Set<object>(), 0);
    const bindings: Record<string, OrganizationReconciliationCompiledTrustBinding> = {};
    for (const [profileId, template] of Object.entries(templates)) {
      if (
        !TRUST_PROFILE_ID.test(profileId) || profileId !== template.profileId ||
        Object.hasOwn(bindings, profileId)
      ) return empty();
      for (const collector of template.requiredCollectors) {
        if (Object.hasOwn(collector, "buildRevision")) return empty();
      }
      const policy = cloneFrozenPolicy(parseOrganizationReconciliationTrustPolicy({
        ...template,
        requiredCollectors: template.requiredCollectors.map((collector) => ({
          ...collector,
          buildRevision
        }))
      }));
      if (!compiledPolicyIsValid(policy)) return empty();
      const profile = cloneFrozenProfile({
        profileId: policy.profileId,
        policySha256: createOrganizationReconciliationTrustPolicySha256(policy),
        expectedEnvironment: policy.environment,
        requiredCollectors: policy.requiredCollectors.map((collector) => ({
          collectorId: collector.collectorId,
          nodeId: collector.nodeId,
          keyId: collector.keyId,
          publicKeySha256: collector.publicKeySha256,
          buildRevision: collector.buildRevision
        }))
      });
      const binding = Object.freeze({ policy, profile });
      if (!compiledBindingIsValid(profileId, binding)) return empty();
      bindings[profileId] = binding;
    }
    return Object.freeze(bindings);
  } catch {
    return empty();
  }
}

/** Pure fail-closed selector used by the emitter and isolated compiler tests. */
export function selectSoleOrganizationReconciliationCompiledTrustBinding(
  registry: OrganizationReconciliationCompiledTrustBindingRegistry
): OrganizationReconciliationCompiledTrustBinding | undefined {
  try {
    assertPlainDataTree(registry, new Set<object>(), 0);
    const entries = Object.entries(registry);
    if (entries.length !== 1) return undefined;
    const [profileId, binding] = entries[0]!;
    if (!compiledBindingIsValid(profileId, binding)) return undefined;
    return cloneFrozenBinding(binding);
  } catch {
    return undefined;
  }
}

/** Canonical JSON bytes for the exact public policy; no profile/private material is emitted. */
export function serializeOrganizationReconciliationCompiledTrustPolicy(
  binding: OrganizationReconciliationCompiledTrustBinding
): string {
  if (!compiledBindingIsValid(binding.profile.profileId, binding)) {
    throw new Error("compiled-trust-policy-mismatch");
  }
  return `${canonicalJson(binding.policy)}\n`;
}

function resolveCompiledBinding(
  profileId: string
): OrganizationReconciliationCompiledTrustBinding | undefined {
  if (!TRUST_PROFILE_ID.test(profileId)) return undefined;
  const binding = selectSoleOrganizationReconciliationCompiledTrustBinding(COMPILED_TRUST_BINDINGS);
  if (!binding || binding.profile.profileId !== profileId) return undefined;
  return binding;
}

function compiledBindingIsValid(
  profileId: string,
  binding: OrganizationReconciliationCompiledTrustBinding
): boolean {
  try {
    assertPlainDataTree(binding, new Set<object>(), 0);
    const policy = parseOrganizationReconciliationTrustPolicy(binding.policy);
    const profile = binding.profile;
    if (
      policy.profileId !== profileId || profile.profileId !== profileId ||
      !compiledPolicyIsValid(policy) || !compiledProfileIsValid(profileId, profile) ||
      profile.expectedEnvironment !== policy.environment ||
      profile.policySha256 !== createOrganizationReconciliationTrustPolicySha256(policy) ||
      profile.requiredCollectors.length !== policy.requiredCollectors.length
    ) return false;
    return profile.requiredCollectors.every((expected, index) => {
      const actual = policy.requiredCollectors[index];
      return actual !== undefined &&
        expected.collectorId === actual.collectorId &&
        expected.nodeId === actual.nodeId &&
        expected.keyId === actual.keyId &&
        expected.publicKeySha256 === actual.publicKeySha256 &&
        expected.buildRevision === actual.buildRevision;
    });
  } catch {
    return false;
  }
}

function compiledPolicyIsValid(policy: OrganizationReconciliationTrustPolicy): boolean {
  const policyStart = Date.parse(policy.validFrom);
  const policyEnd = Date.parse(policy.validUntil);
  if (policyStart >= policyEnd) return false;
  const collectorIds = new Set<string>();
  const nodeIds = new Set<string>();
  const keyIds = new Set<string>();
  const fingerprints = new Set<string>();
  for (const collector of policy.requiredCollectors) {
    const collectorStart = Date.parse(collector.validFrom);
    const collectorEnd = Date.parse(collector.validUntil);
    if (
      collector.buildRevision !== policy.requiredCollectors[0]?.buildRevision ||
      collectorStart >= collectorEnd || collectorStart < policyStart || collectorEnd > policyEnd ||
      collectorIds.has(collector.collectorId) || nodeIds.has(collector.nodeId) ||
      keyIds.has(collector.keyId) || fingerprints.has(collector.publicKeySha256) ||
      !canonicalEd25519SpkiMatchesFingerprint(collector)
    ) return false;
    collectorIds.add(collector.collectorId);
    nodeIds.add(collector.nodeId);
    keyIds.add(collector.keyId);
    fingerprints.add(collector.publicKeySha256);
  }
  return true;
}

function canonicalEd25519SpkiMatchesFingerprint(
  collector: OrganizationReconciliationTrustedCollector
): boolean {
  try {
    if (!collector.publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")) return false;
    const key = createPublicKey(collector.publicKeyPem);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") return false;
    const canonicalPem = key.export({ format: "pem", type: "spki" }).toString();
    if (canonicalPem !== collector.publicKeyPem) return false;
    const der = key.export({ format: "der", type: "spki" });
    return createHash("sha256").update(der).digest("hex") === collector.publicKeySha256;
  } catch {
    return false;
  }
}

function compiledProfileIsValid(
  profileId: string,
  profile: OrganizationReconciliationTrustedProfile
): boolean {
  if (
    profile.profileId !== profileId || !SHA256.test(profile.policySha256) ||
    !TRUST_PROFILE_ID.test(profile.expectedEnvironment) ||
    (profile.expectedEnvironment === "xrteeth-develop"
      ? profile.requiredCollectors.length !== 1
      : profile.requiredCollectors.length < 2 || profile.requiredCollectors.length > 8)
  ) return false;
  const collectorIds = new Set<string>();
  const nodeIds = new Set<string>();
  const keyIds = new Set<string>();
  const fingerprints = new Set<string>();
  for (const collector of profile.requiredCollectors) {
    if (
      !TRUST_PROFILE_ID.test(collector.collectorId) || !TRUST_PROFILE_ID.test(collector.nodeId) ||
      !TRUST_PROFILE_ID.test(collector.keyId) || !FULL_BUILD_REVISION.test(collector.buildRevision) ||
      !SHA256.test(collector.publicKeySha256) || collectorIds.has(collector.collectorId) ||
      nodeIds.has(collector.nodeId) || keyIds.has(collector.keyId) ||
      fingerprints.has(collector.publicKeySha256)
    ) return false;
    collectorIds.add(collector.collectorId);
    nodeIds.add(collector.nodeId);
    keyIds.add(collector.keyId);
    fingerprints.add(collector.publicKeySha256);
  }
  return true;
}

function cloneFrozenBinding(
  binding: OrganizationReconciliationCompiledTrustBinding
): OrganizationReconciliationCompiledTrustBinding {
  return Object.freeze({
    policy: cloneFrozenPolicy(binding.policy),
    profile: cloneFrozenProfile(binding.profile)
  });
}

function cloneFrozenPolicy(
  policy: OrganizationReconciliationTrustPolicy
): OrganizationReconciliationTrustPolicy {
  return Object.freeze({
    ...policy,
    requiredCollectors: Object.freeze(policy.requiredCollectors.map((collector) => Object.freeze({
      ...collector
    })))
  }) as unknown as OrganizationReconciliationTrustPolicy;
}

function cloneFrozenProfile(
  profile: OrganizationReconciliationTrustedProfile
): OrganizationReconciliationTrustedProfile {
  return Object.freeze({
    ...profile,
    requiredCollectors: Object.freeze(profile.requiredCollectors.map((collector) => Object.freeze({
      ...collector
    })))
  }) as unknown as OrganizationReconciliationTrustedProfile;
}

function assertPlainDataTree(candidate: unknown, active: Set<object>, depth: number): void {
  if (candidate === null || typeof candidate !== "object") return;
  if (depth > 16 || active.has(candidate) || isProxy(candidate)) throw new Error("invalid-compiled-trust-data");
  const prototype = Object.getPrototypeOf(candidate);
  if (prototype !== Object.prototype && prototype !== Array.prototype && prototype !== null) {
    throw new Error("invalid-compiled-trust-data");
  }
  if (Object.getOwnPropertySymbols(candidate).length !== 0) throw new Error("invalid-compiled-trust-data");
  active.add(candidate);
  try {
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(candidate))) {
      if (Array.isArray(candidate) && key === "length") continue;
      if (!("value" in descriptor) || !descriptor.enumerable) throw new Error("invalid-compiled-trust-data");
      assertPlainDataTree(descriptor.value, active, depth + 1);
    }
  } finally {
    active.delete(candidate);
  }
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value)!;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("invalid-canonical-json");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new Error("invalid-canonical-json");
}
