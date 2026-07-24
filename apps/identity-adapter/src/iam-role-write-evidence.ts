import { createHash, randomUUID } from "node:crypto";
import type { VerifiedAccessToken } from "./jwt-issuer.service.js";

export interface IamRoleWriteEvidence {
  correlationId: string;
  decision: string;
  route: "change-role" | "people-auth";
  actorFingerprint: string | null;
  matchedSelectorKind: string | null;
}

export function roleWriteCorrelationId(headers: Record<string, string | string[] | undefined>): string {
  const supplied = firstHeader(headers["x-identity-iam-role-write-correlation"]) ?? firstHeader(headers["x-request-id"]);
  return supplied && /^[A-Za-z0-9._:-]{8,128}$/.test(supplied) ? supplied : randomUUID();
}

export function roleWriteActorTokens(claims: VerifiedAccessToken | null): Set<string> {
  if (!claims) {
    return new Set();
  }

  return new Set(
    [
      `legacy:${claims.uid}`,
      `uid:${claims.uid}`,
      `subject:${claims.uid}`,
      claims.username ? `username:${claims.username}` : null
    ]
      .filter((value): value is string => Boolean(value))
      .map(normalizeRoleWriteSelector)
  );
}

export function normalizeRoleWriteSelector(value: string): string {
  const normalized = value.trim().toLowerCase();
  const match = normalized.match(/^(legacy|uid|subject|username):(.+)$/);
  if (!match) {
    return normalized;
  }

  const [, kind, selectorValue] = match;
  const canonicalKind = kind === "subject" ? "uid" : kind;
  return `${canonicalKind}:${selectorValue.trim()}`;
}

export function roleWriteActorFingerprint(claims: VerifiedAccessToken | null): string | null {
  return claims ? shortDigest(`legacy:${claims.uid}`) : null;
}

export function roleWriteSelectorKind(selector: string | null | undefined): string | null {
  const match = selector?.match(/^([a-z]+):/i);
  return match ? (match[1]?.toLowerCase() ?? null) : null;
}

export function roleWriteEvidenceHeaders(evidence: IamRoleWriteEvidence): Record<string, string> {
  return {
    "X-Identity-IAM-Role-Write-Decision": evidence.decision,
    "X-Identity-IAM-Role-Write-Correlation": evidence.correlationId,
    "X-Identity-IAM-Role-Write-Route": evidence.route,
    ...(evidence.actorFingerprint ? { "X-Identity-IAM-Role-Write-Actor": evidence.actorFingerprint } : {}),
    ...(evidence.matchedSelectorKind
      ? { "X-Identity-IAM-Role-Write-Selector-Kind": evidence.matchedSelectorKind }
      : {})
  };
}

function shortDigest(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function firstHeader(value: string | string[] | undefined): string | null {
  return Array.isArray(value) ? value[0] ?? null : value ?? null;
}
