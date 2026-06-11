import { randomUUID } from "node:crypto";
import { BadRequestException, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import {
  LoginAuditSourceEvent,
  UsageBillingRepository,
  UsageLedgerRecord
} from "./usage-billing.repository.js";

const replaySchema = z.object({
  dryRun: z.boolean().optional(),
  afterId: z.number().int().min(0).optional(),
  limit: z.number().int().min(1).max(5000).optional(),
  runKey: z.string().min(8).max(160).optional(),
  rebuildBalance: z.boolean().optional()
});

export type UsageBillingReplayInput = z.infer<typeof replaySchema>;

interface UsageSubject {
  type: "user";
  id: string;
}

@Injectable()
export class UsageBillingService {
  private readonly config = loadConfig();

  constructor(private readonly repository: UsageBillingRepository) {}

  readiness() {
    const { usageBilling } = this.config;

    return {
      shadowEnabled: usageBilling.shadowEnabled,
      dryRunDefault: usageBilling.dryRun,
      repositoryConfigured: this.repository.isConfigured(),
      loginRule: usageBilling.loginRule,
      freeLoginQuota: usageBilling.freeLoginQuota,
      subjectStrategy: usageBilling.subjectStrategy,
      replayBatchSize: usageBilling.replayBatchSize
    };
  }

  async replay(rawInput: unknown) {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for usage billing."
      });
    }

    const input = this.parseReplay(rawInput);
    const dryRun = input.dryRun ?? this.config.usageBilling.dryRun;
    if (!dryRun && !this.config.usageBilling.shadowEnabled) {
      throw new NotFoundException({
        code: "USAGE_BILLING_SHADOW_DISABLED",
        message: "Usage billing shadow calculation is disabled."
      });
    }

    const runKey = input.runKey ?? `usage-billing:${randomUUID()}`;
    const limit = input.limit ?? this.config.usageBilling.replayBatchSize;
    const mode = dryRun ? "dry-run" : "apply";
    const events = await this.repository.listSuccessfulLoginEvents({
      afterId: input.afterId ?? 0,
      limit
    });

    const subjectCounters = new Map<string, number>();
    const records: UsageLedgerRecord[] = [];
    const skipped: Array<{ sourceEventId: number; eventKey: string; reason: string }> = [];

    for (const event of events) {
      const subject = this.resolveSubject(event);
      if (!subject) {
        skipped.push({
          sourceEventId: event.id,
          eventKey: event.eventKey,
          reason: "subject_not_resolved"
        });
        continue;
      }

      const subjectKey = `${subject.type}:${subject.id}`;
      const nextCount = (subjectCounters.get(subjectKey) ?? 0) + 1;
      subjectCounters.set(subjectKey, nextCount);

      records.push(this.buildLedgerRecord(event, subject, nextCount));
    }

    let createdCount = 0;
    let duplicateCount = 0;
    if (!dryRun) {
      await this.repository.createReplayRun({
        runKey,
        mode,
        metadata: this.runMetadata({ dryRun, skipped, plannedCount: records.length })
      });

      try {
        for (const record of records) {
          const result = await this.repository.insertLedger(record);
          if (result.duplicate) {
            duplicateCount += 1;
          } else {
            createdCount += 1;
          }
        }

        let rebuiltBalances = 0;
        if (input.rebuildBalance ?? true) {
          rebuiltBalances = await this.repository.rebuildShadowBalances({
            includedQuota: this.config.usageBilling.freeLoginQuota,
            billingCycle: "default"
          });
        }

        await this.repository.finishReplayRun({
          runKey,
          status: "succeeded",
          processedCount: events.length,
          createdCount,
          skippedCount: skipped.length + duplicateCount,
          metadata: this.runMetadata({ dryRun, skipped, duplicateCount, rebuiltBalances })
        });

        return this.replayResult({ runKey, mode, dryRun, events, records, skipped, createdCount, duplicateCount, rebuiltBalances });
      } catch (error) {
        await this.repository.finishReplayRun({
          runKey,
          status: "failed",
          processedCount: events.length,
          createdCount,
          skippedCount: skipped.length + duplicateCount,
          metadata: this.runMetadata({
            dryRun,
            skipped,
            duplicateCount,
            error: error instanceof Error ? error.message : "unknown error"
          })
        });
        throw error;
      }
    }

    return this.replayResult({ runKey, mode, dryRun, events, records, skipped, createdCount: 0, duplicateCount: 0, rebuiltBalances: 0 });
  }

  async getRun(runKey: string) {
    this.assertConfigured();
    return this.repository.getReplayRun(runKey);
  }

  async getBalance(subjectType: string, subjectId: string) {
    this.assertConfigured();
    return this.repository.getBalance(subjectType, subjectId);
  }

  async listLedger(limit?: number) {
    this.assertConfigured();
    return this.repository.listLedger(limit);
  }

  async loginUsageReport(input: { from?: string; to?: string }) {
    this.assertConfigured();
    const from = parseOptionalDate(input.from, "from");
    const to = parseOptionalDate(input.to, "to");
    const report = await this.repository.getLoginUsageReport({ from, to });

    return {
      ...report,
      from: from?.toISOString() ?? null,
      to: to?.toISOString() ?? null,
      rule: this.config.usageBilling.loginRule,
      shadow: true,
      nonBilling: true
    };
  }

  private parseReplay(rawInput: unknown): UsageBillingReplayInput {
    const parsed = replaySchema.safeParse(rawInput ?? {});
    if (!parsed.success) {
      throw new BadRequestException({
        code: "INVALID_USAGE_BILLING_REPLAY",
        message: "Usage billing replay payload is invalid.",
        details: parsed.error.flatten()
      });
    }

    return parsed.data;
  }

  private assertConfigured(): void {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for usage billing."
      });
    }
  }

  private resolveSubject(event: LoginAuditSourceEvent): UsageSubject | null {
    if (this.config.usageBilling.subjectStrategy !== "user") {
      return null;
    }
    if (event.legacyUserId) {
      return { type: "user", id: `legacy:${event.legacyUserId}` };
    }
    if (event.identityUserId) {
      return { type: "user", id: `identity:${event.identityUserId}` };
    }
    if (event.username) {
      return { type: "user", id: `username:${event.username.toLowerCase()}` };
    }

    return null;
  }

  private buildLedgerRecord(event: LoginAuditSourceEvent, subject: UsageSubject, subjectSequence: number): UsageLedgerRecord {
    const freeQuota = Math.max(0, this.config.usageBilling.freeLoginQuota);
    const chargeMode = subjectSequence <= freeQuota ? "free" : "billable";
    const ledgerKey = `login:${event.id}:${this.config.usageBilling.loginRule}:${subject.type}:${subject.id}`;

    return {
      ledgerKey,
      sourceEventId: event.id,
      subjectType: subject.type,
      subjectId: subject.id,
      usageType: "login",
      quantity: 1,
      unit: "times",
      chargeMode,
      billingStatus: "shadow",
      occurredAt: event.occurredAt,
      metadata: {
        rule: this.config.usageBilling.loginRule,
        sourceEventKey: event.eventKey,
        source: event.source,
        shadow: true
      }
    };
  }

  private replayResult(input: {
    runKey: string;
    mode: string;
    dryRun: boolean;
    events: LoginAuditSourceEvent[];
    records: UsageLedgerRecord[];
    skipped: Array<{ sourceEventId: number; eventKey: string; reason: string }>;
    createdCount: number;
    duplicateCount: number;
    rebuiltBalances: number;
  }) {
    const freeCount = input.records.filter((record) => record.chargeMode === "free").length;
    const billableCount = input.records.filter((record) => record.chargeMode === "billable").length;

    return {
      runKey: input.runKey,
      mode: input.mode,
      dryRun: input.dryRun,
      shadowEnabled: this.config.usageBilling.shadowEnabled,
      rule: this.config.usageBilling.loginRule,
      summary: {
        processedEvents: input.events.length,
        plannedLedgerRecords: input.records.length,
        createdLedgerRecords: input.createdCount,
        duplicateLedgerRecords: input.duplicateCount,
        skippedEvents: input.skipped.length,
        freeLoginRecords: freeCount,
        billableLoginRecords: billableCount,
        rebuiltBalances: input.rebuiltBalances
      },
      skipped: input.skipped,
      plannedRecords: input.dryRun
        ? input.records.map((record) => ({
            ledgerKey: record.ledgerKey,
            sourceEventId: record.sourceEventId,
            subjectType: record.subjectType,
            subjectId: record.subjectId,
            usageType: record.usageType,
            quantity: record.quantity,
            chargeMode: record.chargeMode,
            billingStatus: record.billingStatus,
            occurredAt: record.occurredAt.toISOString()
          }))
        : undefined,
      nonBilling: true
    };
  }

  private runMetadata(input: Record<string, unknown>): Record<string, unknown> {
    return {
      rule: this.config.usageBilling.loginRule,
      subjectStrategy: this.config.usageBilling.subjectStrategy,
      nonBilling: true,
      ...input
    };
  }
}

function parseOptionalDate(value: string | undefined, field: string): Date | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new BadRequestException({
      code: "INVALID_USAGE_BILLING_REPORT_DATE",
      message: `${field} must be a valid date.`
    });
  }

  return parsed;
}
