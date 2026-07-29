export type IdentityNativeRoleWriteTargetMode = "single-target" | "allowlist" | "full";

export interface IdentityNativeRoleWriteTargetConfig {
  roleWriteIdentityNativeTargetMode: IdentityNativeRoleWriteTargetMode;
  roleWriteIdentityNativeTargetLegacyUserId: number;
  roleWriteIdentityNativeTargetAllowlist: string;
  roleWriteRolloutMode: "off" | "canary" | "percentage" | "full";
}

export interface IdentityNativeRoleWriteTargetScope {
  mode: IdentityNativeRoleWriteTargetMode;
  configured: boolean;
  targetCount: number | null;
  missingCapabilities: string[];
}

export interface IdentityNativeRoleWriteTargetDecision {
  owned: boolean;
  mode: IdentityNativeRoleWriteTargetMode;
  reason:
    | "single_target_owned"
    | "target_allowlist_owned"
    | "full_non_root_target_owned"
    | "legacy_root_retained"
    | "target_not_owned";
}

export function identityNativeRoleWriteTargetScope(
  config: IdentityNativeRoleWriteTargetConfig
): IdentityNativeRoleWriteTargetScope {
  const allowlist = parseTargetAllowlist(config.roleWriteIdentityNativeTargetAllowlist);
  const missingCapabilities: string[] = [];

  if (allowlist.invalidCount > 0) {
    missingCapabilities.push("identity-native-target-allowlist-invalid");
  }

  if (config.roleWriteIdentityNativeTargetMode === "single-target") {
    if (config.roleWriteIdentityNativeTargetLegacyUserId <= 0) {
      missingCapabilities.push("single-target-legacy-user-id");
    }
    if (allowlist.ids.size > 0) {
      missingCapabilities.push("single-target-allowlist-must-be-empty");
    }
    return {
      mode: "single-target",
      configured: missingCapabilities.length === 0,
      targetCount: config.roleWriteIdentityNativeTargetLegacyUserId > 0 ? 1 : 0,
      missingCapabilities
    };
  }

  if (config.roleWriteIdentityNativeTargetLegacyUserId > 0) {
    missingCapabilities.push("single-target-legacy-user-id-must-be-zero");
  }

  if (config.roleWriteIdentityNativeTargetMode === "allowlist") {
    if (allowlist.ids.size === 0) {
      missingCapabilities.push("identity-native-target-allowlist-empty");
    }
    return {
      mode: "allowlist",
      configured: missingCapabilities.length === 0,
      targetCount: allowlist.ids.size,
      missingCapabilities
    };
  }

  if (allowlist.ids.size > 0) {
    missingCapabilities.push("full-target-allowlist-must-be-empty");
  }
  if (config.roleWriteRolloutMode !== "full") {
    missingCapabilities.push("full-target-requires-full-operator-rollout");
  }
  return {
    mode: "full",
    configured: missingCapabilities.length === 0,
    targetCount: null,
    missingCapabilities
  };
}

export function identityNativeRoleWriteTargetDecision(
  config: IdentityNativeRoleWriteTargetConfig,
  legacyUserId: number
): IdentityNativeRoleWriteTargetDecision {
  const scope = identityNativeRoleWriteTargetScope(config);
  if (!scope.configured || !Number.isInteger(legacyUserId) || legacyUserId <= 0) {
    return { owned: false, mode: scope.mode, reason: "target_not_owned" };
  }

  if (scope.mode === "single-target") {
    const owned = config.roleWriteIdentityNativeTargetLegacyUserId === legacyUserId;
    return { owned, mode: scope.mode, reason: owned ? "single_target_owned" : "target_not_owned" };
  }

  if (scope.mode === "allowlist") {
    const owned = parseTargetAllowlist(config.roleWriteIdentityNativeTargetAllowlist).ids.has(legacyUserId);
    return { owned, mode: scope.mode, reason: owned ? "target_allowlist_owned" : "target_not_owned" };
  }

  return { owned: true, mode: scope.mode, reason: "full_non_root_target_owned" };
}

function parseTargetAllowlist(value: string): { ids: Set<number>; invalidCount: number } {
  const tokens = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const ids = new Set<number>();
  let invalidCount = 0;

  for (const token of tokens) {
    if (!/^[1-9]\d*$/.test(token)) {
      invalidCount += 1;
      continue;
    }
    const id = Number(token);
    if (!Number.isSafeInteger(id)) {
      invalidCount += 1;
      continue;
    }
    ids.add(id);
  }

  return { ids, invalidCount };
}
