import { createHash } from "node:crypto";
import type { IdentityConfig } from "./config.js";

export type IamAuthzReadMode = "legacy" | "shadow" | "identity-primary";
export type IamAuthzRolloutMode = "off" | "allowlist" | "percentage" | "full";
export type IamAuthzDecision = "allow" | "deny";
export type IamAuthzEvidenceSeverity = "none" | "p0" | "p1" | "info";
export type IamAuthzResponseSource = "legacy" | "identity" | "legacy-fallback" | "fail-closed";

type IamConfig = IdentityConfig["iam"];

export interface IamAuthzSubject {
  legacyUserId?: number;
  username?: string;
  identityUserId?: string;
  subject?: string;
}

export interface IamAuthzReadSelection {
  configuredMode: IamAuthzReadMode;
  effectiveMode: IamAuthzReadMode;
  rolloutMode: IamAuthzRolloutMode;
  rolloutPercentage: number;
  rolloutBucket: number | null;
  selectedForIdentityPrimary: boolean;
  compareIdentity: boolean;
  sourceOfTruth: "legacy" | "identity";
  reason:
    | "legacy_mode"
    | "shadow_mode"
    | "subject_missing"
    | "rollout_off"
    | "allowlist_subject_selected"
    | "allowlist_subject_not_selected"
    | "percentage_subject_selected"
    | "percentage_subject_not_selected"
    | "full_rollout";
  subjectHash: string | null;
}

export interface IamAuthzDecisionEvidenceInput {
  requestKey?: string;
  permission: string;
  resourceType?: "api" | "route" | "plugin";
  subject: IamAuthzSubject;
  legacyDecision: IamAuthzDecision;
  legacyPolicyVersion?: string;
  identityDecision?: IamAuthzDecision;
  identityPolicyVersion?: string;
  identityErrorCode?: string;
}

export interface IamAuthzDecisionEvidence {
  severity: IamAuthzEvidenceSeverity;
  classification:
    | "match"
    | "legacy_deny_identity_allow"
    | "legacy_allow_identity_deny"
    | "identity_read_error"
    | "identity_decision_missing"
    | "identity_policy_version_missing";
  decisionsMatch: boolean | null;
  legacyDecision: IamAuthzDecision;
  identityDecision: IamAuthzDecision | null;
  identityErrorCode: string | null;
  legacyPolicyVersion: string | null;
  identityPolicyVersion: string | null;
  permissionHash: string;
  requestKeyHash: string | null;
  resourceType: "api" | "route" | "plugin";
}

export interface IamAuthzDecisionResult {
  selection: IamAuthzReadSelection;
  outcome: {
    decision: IamAuthzDecision;
    responseSource: IamAuthzResponseSource;
    fallbackUsed: boolean;
    failClosed: boolean;
  };
  evidence: IamAuthzDecisionEvidence;
  safety: {
    permissionUnionApplied: false;
    semanticMismatchFallbackAllowed: false;
    legacyAuthoritativeByDefault: true;
  };
}

export function iamAuthzReadiness(iam: IamConfig) {
  const allowlist = parseAllowlist(iam.authzRolloutAllowlist);
  return {
    readMode: iam.authzReadMode,
    fallbackEnabled: iam.authzFallbackEnabled,
    rollout: {
      mode: iam.authzRolloutMode,
      percentage: boundedPercentage(iam.authzRolloutPercentage),
      allowlistEntryCount: allowlist.size,
      selectionConfigured:
        iam.authzReadMode === "identity-primary" &&
        (iam.authzRolloutMode === "full" ||
          (iam.authzRolloutMode === "allowlist" && allowlist.size > 0) ||
          (iam.authzRolloutMode === "percentage" && boundedPercentage(iam.authzRolloutPercentage) > 0)),
      unselectedBehavior: "legacy"
    },
    safety: {
      rejectsPermissionUnion: true,
      semanticMismatchFallbackAllowed: false,
      identityReadErrorFallbackOnly: true,
      runtimeRouteIntegrationEnabled: false
    }
  };
}

export function decideIamAuthzRead(iam: IamConfig, subject: IamAuthzSubject): IamAuthzReadSelection {
  const subjectKey = stableSubjectKey(subject);
  const subjectHash = subjectKey ? hashValue(subjectKey) : null;
  const rolloutPercentage = boundedPercentage(iam.authzRolloutPercentage);

  if (!subjectKey) {
    return selection(iam, subjectHash, rolloutPercentage, null, false, false, "legacy", "subject_missing");
  }

  if (iam.authzReadMode === "legacy") {
    return selection(iam, subjectHash, rolloutPercentage, null, false, false, "legacy", "legacy_mode");
  }
  if (iam.authzReadMode === "shadow") {
    return selection(iam, subjectHash, rolloutPercentage, null, false, true, "legacy", "shadow_mode");
  }
  if (iam.authzRolloutMode === "off") {
    return selection(iam, subjectHash, rolloutPercentage, null, false, false, "legacy", "rollout_off");
  }
  if (iam.authzRolloutMode === "full") {
    return selection(iam, subjectHash, rolloutPercentage, null, true, false, "identity", "full_rollout");
  }
  if (iam.authzRolloutMode === "allowlist") {
    const selected = subjectTokens(subject).some((token) => parseAllowlist(iam.authzRolloutAllowlist).has(token));
    return selection(
      iam,
      subjectHash,
      rolloutPercentage,
      null,
      selected,
      false,
      selected ? "identity" : "legacy",
      selected ? "allowlist_subject_selected" : "allowlist_subject_not_selected"
    );
  }

  const rolloutBucket = stablePercentageBucket(subjectKey);
  const selected = rolloutBucket < rolloutPercentage;
  return selection(
    iam,
    subjectHash,
    rolloutPercentage,
    rolloutBucket,
    selected,
    false,
    selected ? "identity" : "legacy",
    selected ? "percentage_subject_selected" : "percentage_subject_not_selected"
  );
}

export function decideIamAuthorization(iam: IamConfig, input: IamAuthzDecisionEvidenceInput): IamAuthzDecisionResult {
  const selectionResult = decideIamAuthzRead(iam, input.subject);
  const evidence = classifyIamAuthzEvidence(input);
  let decision = input.legacyDecision;
  let responseSource: IamAuthzResponseSource = "legacy";
  let fallbackUsed = false;
  let failClosed = false;

  if (selectionResult.sourceOfTruth === "identity") {
    if (input.identityErrorCode) {
      if (iam.authzFallbackEnabled) {
        responseSource = "legacy-fallback";
        fallbackUsed = true;
      } else {
        decision = "deny";
        responseSource = "fail-closed";
        failClosed = true;
      }
    } else if (!input.identityDecision || !input.identityPolicyVersion) {
      decision = "deny";
      responseSource = "fail-closed";
      failClosed = true;
    } else if (evidence.severity === "p0") {
      decision = "deny";
      responseSource = "fail-closed";
      failClosed = true;
    } else {
      decision = input.identityDecision;
      responseSource = "identity";
    }
  }

  return {
    selection: selectionResult,
    outcome: {
      decision,
      responseSource,
      fallbackUsed,
      failClosed
    },
    evidence,
    safety: {
      permissionUnionApplied: false,
      semanticMismatchFallbackAllowed: false,
      legacyAuthoritativeByDefault: true
    }
  };
}

export function classifyIamAuthzEvidence(input: IamAuthzDecisionEvidenceInput): IamAuthzDecisionEvidence {
  const common = {
    legacyDecision: input.legacyDecision,
    identityDecision: input.identityDecision ?? null,
    identityErrorCode: input.identityErrorCode ?? null,
    legacyPolicyVersion: input.legacyPolicyVersion ?? null,
    identityPolicyVersion: input.identityPolicyVersion ?? null,
    permissionHash: hashValue(input.permission.trim().toLowerCase()),
    requestKeyHash: input.requestKey ? hashValue(input.requestKey.trim()) : null,
    resourceType: input.resourceType ?? ("api" as const)
  };

  if (input.identityErrorCode) {
    return { ...common, severity: "info", classification: "identity_read_error", decisionsMatch: null };
  }
  if (!input.identityDecision) {
    return { ...common, severity: "p1", classification: "identity_decision_missing", decisionsMatch: null };
  }
  if (!input.identityPolicyVersion) {
    return { ...common, severity: "p1", classification: "identity_policy_version_missing", decisionsMatch: null };
  }
  if (input.legacyDecision === input.identityDecision) {
    return { ...common, severity: "none", classification: "match", decisionsMatch: true };
  }
  if (input.legacyDecision === "deny" && input.identityDecision === "allow") {
    return {
      ...common,
      severity: "p0",
      classification: "legacy_deny_identity_allow",
      decisionsMatch: false
    };
  }
  return {
    ...common,
    severity: "p1",
    classification: "legacy_allow_identity_deny",
    decisionsMatch: false
  };
}

export function stablePercentageBucket(subjectKey: string): number {
  const digest = createHash("sha256").update(subjectKey).digest();
  return digest.readUInt32BE(0) % 100;
}

function selection(
  iam: IamConfig,
  subjectHash: string | null,
  rolloutPercentage: number,
  rolloutBucket: number | null,
  selectedForIdentityPrimary: boolean,
  compareIdentity: boolean,
  sourceOfTruth: "legacy" | "identity",
  reason: IamAuthzReadSelection["reason"]
): IamAuthzReadSelection {
  return {
    configuredMode: iam.authzReadMode,
    effectiveMode: sourceOfTruth === "identity" ? "identity-primary" : iam.authzReadMode === "shadow" ? "shadow" : "legacy",
    rolloutMode: iam.authzRolloutMode,
    rolloutPercentage,
    rolloutBucket,
    selectedForIdentityPrimary,
    compareIdentity,
    sourceOfTruth,
    reason,
    subjectHash
  };
}

function stableSubjectKey(subject: IamAuthzSubject): string | null {
  if (Number.isInteger(subject.legacyUserId) && Number(subject.legacyUserId) > 0) {
    return `legacy:${subject.legacyUserId}`;
  }
  if (subject.identityUserId?.trim()) {
    return `identity:${subject.identityUserId.trim().toLowerCase()}`;
  }
  if (subject.username?.trim()) {
    return `username:${subject.username.trim().toLowerCase()}`;
  }
  if (subject.subject?.trim()) {
    return `subject:${subject.subject.trim().toLowerCase()}`;
  }
  return null;
}

function subjectTokens(subject: IamAuthzSubject): string[] {
  const tokens = new Set<string>();
  if (Number.isInteger(subject.legacyUserId) && Number(subject.legacyUserId) > 0) {
    tokens.add(String(subject.legacyUserId));
    tokens.add(`legacy:${subject.legacyUserId}`);
    tokens.add(`uid:${subject.legacyUserId}`);
  }
  if (subject.identityUserId?.trim()) {
    const value = subject.identityUserId.trim().toLowerCase();
    tokens.add(value);
    tokens.add(`identity:${value}`);
  }
  if (subject.username?.trim()) {
    const value = subject.username.trim().toLowerCase();
    tokens.add(value);
    tokens.add(`username:${value}`);
  }
  if (subject.subject?.trim()) {
    const value = subject.subject.trim().toLowerCase();
    tokens.add(value);
    tokens.add(`subject:${value}`);
  }
  return [...tokens];
}

function parseAllowlist(value: string): ReadonlySet<string> {
  return new Set(
    value
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean)
  );
}

function boundedPercentage(value: number): number {
  return Math.min(100, Math.max(0, Math.trunc(value)));
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
