import { describe, expect, it } from "vitest";
import {
  identityNativeRoleWriteTargetDecision,
  identityNativeRoleWriteTargetScope,
  type IdentityNativeRoleWriteTargetConfig
} from "../src/iam-role-write-target-control.js";

const defaultConfig: IdentityNativeRoleWriteTargetConfig = {
  roleWriteIdentityNativeTargetMode: "single-target",
  roleWriteIdentityNativeTargetLegacyUserId: 0,
  roleWriteIdentityNativeTargetAllowlist: "",
  roleWriteRolloutMode: "off"
};

describe("identity-native role-write target control", () => {
  it("keeps the default single-target scope closed", () => {
    expect(identityNativeRoleWriteTargetScope(defaultConfig)).toEqual({
      mode: "single-target",
      configured: false,
      targetCount: 0,
      missingCapabilities: ["single-target-legacy-user-id"]
    });
    expect(identityNativeRoleWriteTargetDecision(defaultConfig, 25).owned).toBe(false);
  });

  it("selects only the configured single target", () => {
    const config = { ...defaultConfig, roleWriteIdentityNativeTargetLegacyUserId: 25 };
    expect(identityNativeRoleWriteTargetScope(config).configured).toBe(true);
    expect(identityNativeRoleWriteTargetDecision(config, 25)).toMatchObject({
      owned: true,
      mode: "single-target",
      reason: "single_target_owned"
    });
    expect(identityNativeRoleWriteTargetDecision(config, 26).owned).toBe(false);
  });

  it("supports a deduplicated positive-integer target allowlist", () => {
    const config: IdentityNativeRoleWriteTargetConfig = {
      ...defaultConfig,
      roleWriteIdentityNativeTargetMode: "allowlist",
      roleWriteIdentityNativeTargetAllowlist: "25, 26,25",
      roleWriteRolloutMode: "canary"
    };
    expect(identityNativeRoleWriteTargetScope(config)).toEqual({
      mode: "allowlist",
      configured: true,
      targetCount: 2,
      missingCapabilities: []
    });
    expect(identityNativeRoleWriteTargetDecision(config, 25).owned).toBe(true);
    expect(identityNativeRoleWriteTargetDecision(config, 26).owned).toBe(true);
    expect(identityNativeRoleWriteTargetDecision(config, 27).owned).toBe(false);
  });

  it("fails closed for malformed or ambiguous target controls", () => {
    expect(identityNativeRoleWriteTargetScope({
      ...defaultConfig,
      roleWriteIdentityNativeTargetMode: "allowlist",
      roleWriteIdentityNativeTargetLegacyUserId: 25,
      roleWriteIdentityNativeTargetAllowlist: "26,not-an-id",
      roleWriteRolloutMode: "canary"
    })).toMatchObject({
      configured: false,
      missingCapabilities: expect.arrayContaining([
        "identity-native-target-allowlist-invalid",
        "single-target-legacy-user-id-must-be-zero"
      ])
    });
  });

  it("requires a clean full target scope and full operator rollout", () => {
    expect(identityNativeRoleWriteTargetScope({
      ...defaultConfig,
      roleWriteIdentityNativeTargetMode: "full",
      roleWriteRolloutMode: "canary"
    })).toMatchObject({
      configured: false,
      missingCapabilities: ["full-target-requires-full-operator-rollout"]
    });

    const full: IdentityNativeRoleWriteTargetConfig = {
      ...defaultConfig,
      roleWriteIdentityNativeTargetMode: "full",
      roleWriteRolloutMode: "full"
    };
    expect(identityNativeRoleWriteTargetScope(full)).toEqual({
      mode: "full",
      configured: true,
      targetCount: null,
      missingCapabilities: []
    });
    expect(identityNativeRoleWriteTargetDecision(full, 987)).toMatchObject({
      owned: true,
      mode: "full",
      reason: "full_non_root_target_owned"
    });
  });
});
