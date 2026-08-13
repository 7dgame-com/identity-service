export const ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF = "org:public" as const;
export const ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF =
  "org:platform-global" as const;
export const ORGANIZATION_RECONCILIATION_PROJECTION_CATALOGS_READY = false as const;

export type AuthorizationContextKind = "organization" | "platform-global" | "public";

export interface AuthorizationContext {
  readonly contextKind: AuthorizationContextKind;
  readonly contextRef: string;
}

export function canonicalLegacyOrganizationId(value: string | number): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error("A Legacy organization ID is invalid.");
    return String(value);
  }
  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    throw new Error("A Legacy organization ID is invalid.");
  }
  return value;
}

export function organizationRefForLegacyId(legacyOrganizationId: string | number): string {
  return `legacy-org:${canonicalLegacyOrganizationId(legacyOrganizationId)}`;
}

export function subjectRefForLegacyUserId(legacyUserId: string | number): string {
  return `legacy-user:${canonicalLegacyUserId(legacyUserId)}`;
}

export function pluginRefForId(pluginId: string): string {
  const canonicalPluginId = canonicalReconciliationToken(pluginId, "plugin ID");
  if (canonicalPluginId.startsWith("plugin:")) {
    throw new Error("The plugin ID must not include the plugin namespace prefix.");
  }
  // Keep this identical to the system-admin owner contract. Accepting a
  // reconciliation-only superset would admit impossible/confusable plugin
  // identities into a signed authorization universe.
  if (!/^[A-Za-z0-9-]{1,64}$/.test(canonicalPluginId)) {
    throw new Error("The plugin ID is not a canonical ID token.");
  }
  return `plugin:${canonicalPluginId}`;
}

export function isCanonicalLegacyUserSubjectRef(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^legacy-user:([1-9]\d*)$/.exec(value);
  if (!match) return false;
  try {
    return subjectRefForLegacyUserId(match[1]!) === value;
  } catch {
    return false;
  }
}

export function isCanonicalPluginRef(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("plugin:")) return false;
  try {
    return pluginRefForId(value.slice("plugin:".length)) === value;
  } catch {
    return false;
  }
}

export function isCanonicalLegacyOrganizationId(value: unknown): value is string | number {
  if (typeof value !== "string" && typeof value !== "number") return false;
  try {
    canonicalLegacyOrganizationId(value);
    return true;
  } catch {
    return false;
  }
}

export function isCanonicalOrganizationRef(
  value: unknown,
  publicAllowed: boolean
): value is string {
  if (value === ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF) return publicAllowed;
  if (typeof value !== "string") return false;
  const match = /^legacy-org:([1-9]\d*)$/.exec(value);
  if (!match) return false;
  try {
    return organizationRefForLegacyId(match[1]!) === value;
  } catch {
    return false;
  }
}

/**
 * Validates the authorization-context namespace without widening the generic
 * organization-ref predicate above. The kind/ref pair is a strict bijection:
 * organization contexts use only legacy-org:<canonical-id>, while the two
 * non-organization contexts each have exactly one reserved ref.
 */
export function isCanonicalAuthorizationContext(
  contextKind: unknown,
  contextRef: unknown
): contextKind is AuthorizationContextKind {
  if (contextKind === "platform-global") {
    return contextRef === ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF;
  }
  if (contextKind === "public") {
    return contextRef === ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF;
  }
  return contextKind === "organization" && isCanonicalOrganizationRef(contextRef, false);
}

export function authorizationContextForLegacyOrganizationId(
  legacyOrganizationId: string | number
): Readonly<AuthorizationContext> {
  return Object.freeze({
    contextKind: "organization" as const,
    contextRef: organizationRefForLegacyId(legacyOrganizationId)
  });
}

export function platformGlobalAuthorizationContext(): Readonly<AuthorizationContext> {
  return Object.freeze({
    contextKind: "platform-global" as const,
    contextRef: ORGANIZATION_RECONCILIATION_PLATFORM_GLOBAL_CONTEXT_REF
  });
}

export function publicAuthorizationContext(): Readonly<AuthorizationContext> {
  return Object.freeze({
    contextKind: "public" as const,
    contextRef: ORGANIZATION_RECONCILIATION_PUBLIC_CONTEXT_REF
  });
}

export function isCanonicalReconciliationToken(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    canonicalReconciliationToken(value, "record value");
    return true;
  } catch {
    return false;
  }
}

export function canonicalReconciliationToken(value: string, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    value.trim() !== value ||
    value.normalize("NFC") !== value ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`The ${label} is not canonical.`);
  }
  return value;
}

function canonicalLegacyUserId(value: string | number): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error("A Legacy user ID is invalid.");
    return String(value);
  }
  if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
    throw new Error("A Legacy user ID is invalid.");
  }
  return value;
}
