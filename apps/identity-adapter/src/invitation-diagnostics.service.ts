import { Injectable } from "@nestjs/common";
import { InvitationRecordRepository, InvitationRecordStats } from "./invitation-record.repository.js";
import { InvitationRedisReader, LegacyRedisInvitation, LegacyRedisInvitationScan } from "./invitation-redis.reader.js";

export interface InvitationDiagnosticsReport {
  checkedAt: string;
  filter: {
    code: string | null;
  };
  sources: {
    legacyRedisConfigured: boolean;
    legacyDatabaseConfigured: boolean;
  };
  redis: LegacyRedisInvitationScan;
  records: InvitationRecordStats;
  consistency: {
    checked: boolean;
    issues: InvitationConsistencyIssue[];
  };
  legacyRedisSchema: Record<string, string>;
}

export interface InvitationConsistencyIssue {
  code: string;
  type: string;
  message: string;
  severity: "warning" | "error";
  details?: Record<string, unknown>;
}

@Injectable()
export class InvitationDiagnosticsService {
  constructor(
    private readonly redisReader: InvitationRedisReader,
    private readonly records: InvitationRecordRepository
  ) {}

  async diagnostics(code?: string | null): Promise<InvitationDiagnosticsReport> {
    const normalizedCode = code?.trim() || null;
    const redis = await this.redisReader.scanInvitations(normalizedCode);
    const records = await this.records.getStats(normalizedCode);
    const consistency = buildConsistency(redis, records);

    return {
      checkedAt: new Date().toISOString(),
      filter: {
        code: normalizedCode
      },
      sources: {
        legacyRedisConfigured: redis.configured,
        legacyDatabaseConfigured: records.configured
      },
      redis,
      records,
      consistency,
      legacyRedisSchema: {
        quota: "邀请码总名额",
        remaining: "当前剩余名额",
        expiresAt: "Unix 秒级过期时间",
        creatorId: "创建者旧用户 id",
        creatorName: "创建者显示名",
        note: "备注",
        createdAt: "Unix 秒级创建时间"
      }
    };
  }
}

function buildConsistency(redis: LegacyRedisInvitationScan, records: InvitationRecordStats): InvitationDiagnosticsReport["consistency"] {
  if (!redis.configured || !records.configured) {
    return {
      checked: false,
      issues: [
        ...(!redis.configured ? [sourceIssue("legacy_redis_not_configured", "Legacy Redis is not configured.")] : []),
        ...(!records.configured ? [sourceIssue("legacy_database_not_configured", "Legacy database is not configured.")] : [])
      ]
    };
  }

  const issues: InvitationConsistencyIssue[] = [];
  const recordCountByCode = new Map(records.byCode.map((record) => [record.inviteCode, record.recordCount]));
  const invitationCodes = new Set<string>();

  for (const invitation of redis.invitations) {
    invitationCodes.add(invitation.code);
    issues.push(...validateInvitationShape(invitation));
    if (invitation.quota !== null && invitation.remaining !== null) {
      const expectedUsed = Math.max(0, invitation.quota - invitation.remaining);
      const actualRecords = recordCountByCode.get(invitation.code) ?? 0;
      if (actualRecords > expectedUsed) {
        issues.push({
          code: invitation.code,
          type: "record_count_exceeds_used_quota",
          severity: "warning",
          message: "邀请注册记录数大于 Redis 已使用名额，切换 native 前需要人工确认。",
          details: {
            quota: invitation.quota,
            remaining: invitation.remaining,
            expectedUsed,
            actualRecords
          }
        });
      }
    }
  }

  for (const record of records.byCode) {
    if (!invitationCodes.has(record.inviteCode)) {
      issues.push({
        code: record.inviteCode,
        type: "record_without_redis_invite",
        severity: "warning",
        message: "旧 MySQL 存在注册记录，但 Redis 中没有对应邀请码。历史邀请码可能已过期或删除。",
        details: {
          recordCount: record.recordCount,
          firstCreatedAt: record.firstCreatedAt,
          lastCreatedAt: record.lastCreatedAt
        }
      });
    }
  }

  return {
    checked: true,
    issues
  };
}

function validateInvitationShape(invitation: LegacyRedisInvitation): InvitationConsistencyIssue[] {
  const issues: InvitationConsistencyIssue[] = [];
  const requiredNumericFields: Array<keyof Pick<LegacyRedisInvitation, "quota" | "remaining" | "expiresAt" | "createdAt">> = [
    "quota",
    "remaining",
    "expiresAt",
    "createdAt"
  ];
  for (const field of requiredNumericFields) {
    if (invitation[field] === null) {
      issues.push({
        code: invitation.code,
        type: `missing_${field}`,
        severity: "error",
        message: `Redis invite is missing numeric field ${field}.`
      });
    }
  }
  if (invitation.quota !== null && invitation.quota < 1) {
    issues.push({
      code: invitation.code,
      type: "invalid_quota",
      severity: "error",
      message: "Redis invite quota must be greater than zero.",
      details: {
        quota: invitation.quota
      }
    });
  }
  if (invitation.remaining !== null && invitation.remaining < 0) {
    issues.push({
      code: invitation.code,
      type: "negative_remaining",
      severity: "error",
      message: "Redis invite remaining quota is negative.",
      details: {
        remaining: invitation.remaining
      }
    });
  }

  return issues;
}

function sourceIssue(type: string, message: string): InvitationConsistencyIssue {
  return {
    code: "*",
    type,
    severity: "warning",
    message
  };
}
