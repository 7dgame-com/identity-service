/**
 * Compiled-only readiness facts. None can be promoted by input, environment,
 * or an adapter instance supplied at runtime.
 */
export const ORGANIZATION_RECONCILIATION_RAW_SOURCE_CAPABILITY_READY = false as const;
/**
 * The private factory-origin brand exists, but no compiled production binding
 * consumes it yet. Implementation must never be confused with readiness.
 */
export const ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_IMPLEMENTED =
  true as const;
export const ORGANIZATION_RECONCILIATION_TRANSACTION_ADAPTER_FACTORY_CAPABILITY_READY = false as const;
export const ORGANIZATION_RECONCILIATION_COMPILED_PIPELINE_REGISTRATION_READY = false as const;
