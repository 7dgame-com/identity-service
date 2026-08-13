import { createHash } from "node:crypto";

export interface IdentityNativeOrganizationWriteTargetConfig {
  organizationWriteRolloutMode: "off" | "allowlist" | "percentage" | "full";
  organizationWriteRolloutAllowlist: string;
  organizationWriteRolloutPercentage: number;
}

export interface IdentityNativeOrganizationWriteTargetDecision {
  owned: boolean;
  mode: IdentityNativeOrganizationWriteTargetConfig["organizationWriteRolloutMode"];
  reason:
    | "target_allowlist_owned"
    | "target_percentage_owned"
    | "full_target_owned"
    | "rollout_off"
    | "target_not_owned"
    | "target_selector_invalid";
  selectorKind: "allowlist" | "percentage" | "full" | null;
  bucket: number | null;
}

export function identityNativeOrganizationWriteTargetDecision(
  config: IdentityNativeOrganizationWriteTargetConfig,
  legacyUserId: number
): IdentityNativeOrganizationWriteTargetDecision {
  if (!Number.isSafeInteger(legacyUserId) || legacyUserId <= 0) {
    return decision(config, false, "target_selector_invalid", null, null);
  }
  if (config.organizationWriteRolloutMode === "off") {
    return decision(config, false, "rollout_off", null, null);
  }
  if (config.organizationWriteRolloutMode === "full") {
    return decision(config, true, "full_target_owned", "full", null);
  }
  if (config.organizationWriteRolloutMode === "allowlist") {
    const allowlist = parseTargetAllowlist(config.organizationWriteRolloutAllowlist);
    if (allowlist.invalidCount > 0 || allowlist.ids.size === 0) {
      return decision(config, false, "target_selector_invalid", null, null);
    }
    const owned = allowlist.ids.has(legacyUserId);
    return decision(config, owned, owned ? "target_allowlist_owned" : "target_not_owned", owned ? "allowlist" : null, null);
  }

  const percentage = Math.trunc(config.organizationWriteRolloutPercentage);
  if (!Number.isSafeInteger(percentage) || percentage <= 0 || percentage > 100) {
    return decision(config, false, "target_selector_invalid", null, null);
  }
  const bucket = Number.parseInt(
    createHash("sha256").update(`legacy:${legacyUserId}`).digest("hex").slice(0, 8),
    16
  ) % 100;
  const owned = bucket < percentage;
  return decision(config, owned, owned ? "target_percentage_owned" : "target_not_owned", "percentage", bucket);
}

export function identityNativeOrganizationWriteTargetScope(
  config: IdentityNativeOrganizationWriteTargetConfig
): { configured: boolean; missingCapabilities: string[]; targetCount: number | null } {
  const missingCapabilities: string[] = [];
  if (config.organizationWriteRolloutMode === "off") {
    missingCapabilities.push("identity-native-target-rollout-off");
  } else if (config.organizationWriteRolloutMode === "allowlist") {
    const allowlist = parseTargetAllowlist(config.organizationWriteRolloutAllowlist);
    if (allowlist.invalidCount > 0) missingCapabilities.push("identity-native-target-allowlist-invalid");
    if (allowlist.ids.size === 0) missingCapabilities.push("identity-native-target-allowlist-empty");
  } else if (config.organizationWriteRolloutMode === "percentage") {
    const percentage = Math.trunc(config.organizationWriteRolloutPercentage);
    if (!Number.isSafeInteger(percentage) || percentage <= 0 || percentage > 100) {
      missingCapabilities.push("identity-native-target-percentage-invalid");
    }
  }
  return {
    configured: missingCapabilities.length === 0,
    missingCapabilities,
    targetCount: config.organizationWriteRolloutMode === "allowlist"
      ? parseTargetAllowlist(config.organizationWriteRolloutAllowlist).ids.size
      : config.organizationWriteRolloutMode === "full" || config.organizationWriteRolloutMode === "percentage"
        ? null
        : 0
  };
}

function decision(
  config: IdentityNativeOrganizationWriteTargetConfig,
  owned: boolean,
  reason: IdentityNativeOrganizationWriteTargetDecision["reason"],
  selectorKind: IdentityNativeOrganizationWriteTargetDecision["selectorKind"],
  bucket: number | null
): IdentityNativeOrganizationWriteTargetDecision {
  return { owned, mode: config.organizationWriteRolloutMode, reason, selectorKind, bucket };
}

function parseTargetAllowlist(value: string): { ids: Set<number>; invalidCount: number } {
  const ids = new Set<number>();
  let invalidCount = 0;
  for (const raw of value.split(",").map((item) => item.trim()).filter(Boolean)) {
    const token = raw.toLowerCase().replace(/^(legacy|uid):/, "");
    if (!/^[1-9]\d*$/.test(token)) {
      invalidCount += 1;
      continue;
    }
    const id = Number(token);
    if (!Number.isSafeInteger(id)) invalidCount += 1;
    else ids.add(id);
  }
  return { ids, invalidCount };
}
