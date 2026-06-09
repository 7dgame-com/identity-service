import { Injectable } from "@nestjs/common";
import { IdentityInvitation, InvitationIdentityRepository, isImportable, statusFromInvitation } from "./invitation-identity.repository.js";
import { InvitationRedisReader, LegacyRedisInvitation } from "./invitation-redis.reader.js";

export interface InvitationImportPlan {
  dryRun: boolean;
  sourceConfigured: boolean;
  identityDbConfigured: boolean;
  scannedKeys: number;
  truncated: boolean;
  summary: {
    create: number;
    update: number;
    unchanged: number;
    skip: number;
  };
  actions: InvitationImportAction[];
}

export interface InvitationImportAction {
  code: string;
  action: "create" | "update" | "unchanged" | "skip";
  reason: string;
  before?: Partial<IdentityInvitation> | null;
  after?: Partial<IdentityInvitation> | null;
  differences?: string[];
}

@Injectable()
export class InvitationImportService {
  constructor(
    private readonly redisReader: InvitationRedisReader,
    private readonly identityInvitations: InvitationIdentityRepository
  ) {}

  async plan(input: { code?: string | null; dryRun?: boolean } = {}): Promise<InvitationImportPlan> {
    const redis = await this.redisReader.scanInvitations(input.code ?? null);
    if (!redis.configured) {
      return emptyPlan(Boolean(input.dryRun ?? true), false, this.identityInvitations.isConfigured(), redis.scannedKeys, redis.truncated, [
        {
          code: "*",
          action: "skip",
          reason: "legacy Redis is not configured"
        }
      ]);
    }
    if (!this.identityInvitations.isConfigured()) {
      return emptyPlan(Boolean(input.dryRun ?? true), true, false, redis.scannedKeys, redis.truncated, [
        {
          code: "*",
          action: "skip",
          reason: "identity database is not configured"
        }
      ]);
    }

    const existing = await this.identityInvitations.findByCodes(redis.invitations.map((invitation) => invitation.code));
    const existingByCode = new Map(existing.map((invitation) => [invitation.inviteCode, invitation]));
    const actions = redis.invitations.map((invitation) => buildAction(invitation, existingByCode.get(invitation.code) ?? null));

    return summarizePlan(Boolean(input.dryRun ?? true), true, true, redis.scannedKeys, redis.truncated, actions);
  }

  async importFromLegacy(input: { code?: string | null; apply?: boolean } = {}): Promise<InvitationImportPlan & { applied: boolean; affectedRows: number }> {
    const dryRun = !input.apply;
    const plan = await this.plan({ code: input.code ?? null, dryRun });
    if (dryRun) {
      return { ...plan, applied: false, affectedRows: 0 };
    }
    const importableCodes = new Set(plan.actions.filter((action) => ["create", "update"].includes(action.action)).map((action) => action.code));
    const redis = await this.redisReader.scanInvitations(input.code ?? null);
    const invitations = redis.invitations.filter((invitation) => importableCodes.has(invitation.code) && isImportable(invitation));
    const affectedRows = await this.identityInvitations.upsertImported(invitations);

    return {
      ...plan,
      dryRun: false,
      applied: true,
      affectedRows
    };
  }
}

function buildAction(invitation: LegacyRedisInvitation, existing: IdentityInvitation | null): InvitationImportAction {
  if (!isImportable(invitation)) {
    return {
      code: invitation.code,
      action: "skip",
      reason: "legacy Redis invite has missing or invalid required fields",
      after: afterFromRedis(invitation)
    };
  }

  const after = afterFromRedis(invitation);
  if (!existing) {
    return {
      code: invitation.code,
      action: "create",
      reason: "invite exists in legacy Redis but not in identity DB",
      before: null,
      after
    };
  }

  const differences = diffInvitation(existing, after);
  if (differences.length === 0) {
    return {
      code: invitation.code,
      action: "unchanged",
      reason: "identity DB already matches legacy Redis",
      before: beforeFromIdentity(existing),
      after
    };
  }

  return {
    code: invitation.code,
    action: "update",
    reason: "identity DB differs from legacy Redis",
    before: beforeFromIdentity(existing),
    after,
    differences
  };
}

function afterFromRedis(invitation: LegacyRedisInvitation): Partial<IdentityInvitation> {
  return {
    inviteCode: invitation.code,
    quota: invitation.quota ?? undefined,
    remaining: invitation.remaining ?? undefined,
    expiresAt: invitation.expiresAt ?? undefined,
    creatorLegacyUserId: invitation.creatorId,
    creatorName: invitation.creatorName,
    note: invitation.note,
    legacyCreatedAt: invitation.createdAt ?? undefined,
    status: statusFromInvitation(invitation),
    source: "legacy-redis"
  };
}

function beforeFromIdentity(invitation: IdentityInvitation): Partial<IdentityInvitation> {
  return {
    inviteCode: invitation.inviteCode,
    quota: invitation.quota,
    remaining: invitation.remaining,
    expiresAt: invitation.expiresAt,
    creatorLegacyUserId: invitation.creatorLegacyUserId,
    creatorName: invitation.creatorName,
    note: invitation.note,
    legacyCreatedAt: invitation.legacyCreatedAt,
    status: invitation.status,
    source: invitation.source
  };
}

function diffInvitation(existing: IdentityInvitation, after: Partial<IdentityInvitation>): string[] {
  const fields: Array<keyof IdentityInvitation> = [
    "quota",
    "remaining",
    "expiresAt",
    "creatorLegacyUserId",
    "creatorName",
    "note",
    "legacyCreatedAt",
    "status",
    "source"
  ];

  return fields.filter((field) => existing[field] !== after[field]);
}

function summarizePlan(
  dryRun: boolean,
  sourceConfigured: boolean,
  identityDbConfigured: boolean,
  scannedKeys: number,
  truncated: boolean,
  actions: InvitationImportAction[]
): InvitationImportPlan {
  return {
    dryRun,
    sourceConfigured,
    identityDbConfigured,
    scannedKeys,
    truncated,
    summary: {
      create: actions.filter((action) => action.action === "create").length,
      update: actions.filter((action) => action.action === "update").length,
      unchanged: actions.filter((action) => action.action === "unchanged").length,
      skip: actions.filter((action) => action.action === "skip").length
    },
    actions
  };
}

function emptyPlan(
  dryRun: boolean,
  sourceConfigured: boolean,
  identityDbConfigured: boolean,
  scannedKeys: number,
  truncated: boolean,
  actions: InvitationImportAction[]
): InvitationImportPlan {
  return summarizePlan(dryRun, sourceConfigured, identityDbConfigured, scannedKeys, truncated, actions);
}
