import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import {
  decideIamAuthorization,
  decideIamAuthzRead,
  iamAuthzReadiness,
  stablePercentageBucket
} from "../src/iam-authz-read-control.js";

describe("IAM authz read controls", () => {
  it("keeps authz reads legacy authoritative and rollout off by default", () => {
    const iam = loadConfig({}).iam;

    expect(iamAuthzReadiness(iam)).toMatchObject({
      readMode: "legacy",
      fallbackEnabled: true,
      rollout: {
        mode: "off",
        percentage: 0,
        allowlistEntryCount: 0,
        selectionConfigured: false,
        unselectedBehavior: "legacy"
      },
      safety: {
        rejectsPermissionUnion: true,
        semanticMismatchFallbackAllowed: false,
        runtimeRouteIntegrationEnabled: false
      }
    });
    expect(decideIamAuthzRead(iam, { legacyUserId: 24 })).toMatchObject({
      configuredMode: "legacy",
      effectiveMode: "legacy",
      selectedForIdentityPrimary: false,
      compareIdentity: false,
      sourceOfTruth: "legacy",
      reason: "legacy_mode"
    });
  });

  it("keeps shadow mode response ownership on legacy while enabling comparison", () => {
    const iam = loadConfig({ IDENTITY_IAM_AUTHZ_READ_MODE: "shadow" }).iam;

    expect(decideIamAuthzRead(iam, { username: "guanfei" })).toMatchObject({
      configuredMode: "shadow",
      effectiveMode: "shadow",
      selectedForIdentityPrimary: false,
      compareIdentity: true,
      sourceOfTruth: "legacy",
      reason: "shadow_mode"
    });
  });

  it("selects only allowlisted subjects for identity-primary", () => {
    const iam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "allowlist",
      IDENTITY_IAM_AUTHZ_ROLLOUT_ALLOWLIST: "username:guanfei,legacy:99"
    }).iam;

    expect(decideIamAuthzRead(iam, { legacyUserId: 24, username: "GuanFei" })).toMatchObject({
      effectiveMode: "identity-primary",
      selectedForIdentityPrimary: true,
      sourceOfTruth: "identity",
      reason: "allowlist_subject_selected"
    });
    expect(decideIamAuthzRead(iam, { legacyUserId: 25, username: "ordinary" })).toMatchObject({
      effectiveMode: "legacy",
      selectedForIdentityPrimary: false,
      sourceOfTruth: "legacy",
      reason: "allowlist_subject_not_selected"
    });
  });

  it("uses a stable percentage bucket and supports full rollout without changing defaults", () => {
    const subject = { legacyUserId: 24 };
    const percentageIam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "percentage",
      IDENTITY_IAM_AUTHZ_ROLLOUT_PERCENTAGE: "25"
    }).iam;
    const first = decideIamAuthzRead(percentageIam, subject);
    const second = decideIamAuthzRead(percentageIam, subject);

    expect(first.rolloutBucket).toBe(stablePercentageBucket("legacy:24"));
    expect(second).toEqual(first);
    expect(first.selectedForIdentityPrimary).toBe(first.rolloutBucket! < 25);

    const fullIam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full"
    }).iam;
    expect(decideIamAuthzRead(fullIam, subject)).toMatchObject({
      effectiveMode: "identity-primary",
      selectedForIdentityPrimary: true,
      sourceOfTruth: "identity",
      reason: "full_rollout"
    });
    expect(decideIamAuthzRead(fullIam, {})).toMatchObject({
      effectiveMode: "legacy",
      selectedForIdentityPrimary: false,
      sourceOfTruth: "legacy",
      reason: "subject_missing",
      subjectHash: null
    });
  });

  it("classifies legacy-deny identity-allow as P0 without semantic fallback or permission union", () => {
    const iam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full",
      IDENTITY_IAM_AUTHZ_FALLBACK_ENABLED: "true"
    }).iam;
    const result = decideIamAuthorization(iam, {
      requestKey: "plugin-open-24",
      permission: "plugin.open",
      resourceType: "plugin",
      subject: { legacyUserId: 24 },
      legacyDecision: "deny",
      legacyPolicyVersion: "legacy-rbac-v1",
      identityDecision: "allow",
      identityPolicyVersion: "candidate-checksum-v2"
    });

    expect(result.outcome).toEqual({
      decision: "deny",
      responseSource: "fail-closed",
      fallbackUsed: false,
      failClosed: true
    });
    expect(result.evidence).toMatchObject({
      severity: "p0",
      classification: "legacy_deny_identity_allow",
      decisionsMatch: false,
      resourceType: "plugin",
      legacyPolicyVersion: "legacy-rbac-v1",
      identityPolicyVersion: "candidate-checksum-v2"
    });
    expect(result.safety).toEqual({
      permissionUnionApplied: false,
      semanticMismatchFallbackAllowed: false,
      legacyAuthoritativeByDefault: true
    });
    expect(JSON.stringify(result)).not.toContain("plugin.open");
  });

  it("classifies legacy-allow identity-deny as P1 and observes a refreshed revoke", () => {
    const iam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full"
    }).iam;
    const base = {
      permission: "course.manage",
      resourceType: "route" as const,
      subject: { legacyUserId: 24 },
      legacyDecision: "allow" as const,
      legacyPolicyVersion: "legacy-rbac-v1"
    };
    const beforeRevoke = decideIamAuthorization(iam, {
      ...base,
      identityDecision: "allow",
      identityPolicyVersion: "candidate-before-revoke"
    });
    const afterRevoke = decideIamAuthorization(iam, {
      ...base,
      identityDecision: "deny",
      identityPolicyVersion: "candidate-after-revoke"
    });

    expect(beforeRevoke.outcome.decision).toBe("allow");
    expect(afterRevoke.outcome).toMatchObject({
      decision: "deny",
      responseSource: "identity",
      fallbackUsed: false
    });
    expect(afterRevoke.evidence).toMatchObject({
      severity: "p1",
      classification: "legacy_allow_identity_deny",
      identityPolicyVersion: "candidate-after-revoke"
    });
  });

  it("uses legacy fallback only for identity read errors and otherwise fails closed", () => {
    const fallbackIam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full",
      IDENTITY_IAM_AUTHZ_FALLBACK_ENABLED: "true"
    }).iam;
    const timeout = decideIamAuthorization(fallbackIam, {
      permission: "system-admin.open",
      subject: { username: "nethz" },
      legacyDecision: "allow",
      identityErrorCode: "IDENTITY_TIMEOUT"
    });

    expect(timeout.outcome).toEqual({
      decision: "allow",
      responseSource: "legacy-fallback",
      fallbackUsed: true,
      failClosed: false
    });
    expect(timeout.evidence).toMatchObject({ severity: "info", classification: "identity_read_error" });

    const failClosedIam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full",
      IDENTITY_IAM_AUTHZ_FALLBACK_ENABLED: "false"
    }).iam;
    expect(
      decideIamAuthorization(failClosedIam, {
        permission: "system-admin.open",
        subject: { username: "nethz" },
        legacyDecision: "allow",
        identityErrorCode: "IDENTITY_TIMEOUT"
      }).outcome
    ).toEqual({
      decision: "deny",
      responseSource: "fail-closed",
      fallbackUsed: false,
      failClosed: true
    });
  });

  it("fails closed when identity decision evidence has no immutable policy version", () => {
    const iam = loadConfig({
      IDENTITY_IAM_AUTHZ_READ_MODE: "identity-primary",
      IDENTITY_IAM_AUTHZ_ROLLOUT_MODE: "full"
    }).iam;
    const result = decideIamAuthorization(iam, {
      permission: "user.manage",
      subject: { identityUserId: "identity-user-24" },
      legacyDecision: "allow",
      identityDecision: "allow"
    });

    expect(result.outcome).toMatchObject({ decision: "deny", responseSource: "fail-closed", failClosed: true });
    expect(result.evidence).toMatchObject({ severity: "p1", classification: "identity_policy_version_missing" });
  });

  it("rejects invalid rollout percentages at config load", () => {
    expect(() => loadConfig({ IDENTITY_IAM_AUTHZ_ROLLOUT_PERCENTAGE: "101" })).toThrow();
    expect(() => loadConfig({ IDENTITY_IAM_AUTHZ_ROLLOUT_PERCENTAGE: "-1" })).toThrow();
    expect(() => loadConfig({ IDENTITY_IAM_AUTHZ_ROLLOUT_PERCENTAGE: "0.5" })).toThrow();
  });
});
