import { createHash, randomUUID } from "node:crypto";

export interface IamOrganizationWriteEvidence {
  correlationId: string;
  decision: string;
  actorFingerprint: string | null;
  targetFingerprint: string | null;
  matchedSelectorKind: string | null;
  identityStatus?: string | null;
}

export function organizationWriteCorrelationId(headers: Record<string, string | string[] | undefined>): string {
  const supplied = firstHeader(headers["x-identity-iam-organization-write-correlation"]) ?? firstHeader(headers["x-request-id"]);
  return supplied && /^[A-Za-z0-9._:-]{8,128}$/.test(supplied) ? supplied : randomUUID();
}

export function organizationWriteFingerprint(value: string | number | null | undefined): string | null {
  return value === null || value === undefined ? null : createHash("sha256").update(String(value)).digest("hex").slice(0, 16);
}

export function organizationWriteEvidenceHeaders(evidence: IamOrganizationWriteEvidence): Record<string, string> {
  return {
    "X-Identity-IAM-Organization-Write-Decision": evidence.decision,
    "X-Identity-IAM-Organization-Write-Correlation": evidence.correlationId,
    "X-Identity-IAM-Organization-Write-Route": "membership-replace",
    ...(evidence.actorFingerprint ? { "X-Identity-IAM-Organization-Write-Actor": evidence.actorFingerprint } : {}),
    ...(evidence.targetFingerprint ? { "X-Identity-IAM-Organization-Write-Target": evidence.targetFingerprint } : {}),
    ...(evidence.matchedSelectorKind
      ? { "X-Identity-IAM-Organization-Write-Selector-Kind": evidence.matchedSelectorKind }
      : {}),
    ...(evidence.identityStatus ? { "X-Identity-IAM-Organization-Write-Identity-Status": evidence.identityStatus } : {})
  };
}

function firstHeader(value: string | string[] | undefined): string | null {
  return Array.isArray(value) ? value[0] ?? null : value ?? null;
}
