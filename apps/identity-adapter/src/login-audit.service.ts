import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { BadRequestException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { LoginAuditIpExposure, LoginAuditRepository } from "./login-audit.repository.js";

const payloadSchema = z.object({
  eventKey: z.string().min(8).max(128),
  legacyUserId: z.number().int().positive().nullable().optional(),
  identityUserId: z.string().min(1).max(128).nullable().optional(),
  username: z.string().min(1).max(255).nullable().optional(),
  eventType: z.string().min(1).max(64).default("login"),
  success: z.boolean().default(true),
  occurredAt: z.union([z.string(), z.number(), z.date()]).optional(),
  ipAddress: z.string().max(255).nullable().optional(),
  userAgent: z.string().max(2048).nullable().optional(),
  source: z.string().min(1).max(64).default("legacy-backend"),
  traceId: z.string().max(128).nullable().optional(),
  metadata: z.record(z.unknown()).nullable().optional()
});

export type LoginAuditPayload = z.infer<typeof payloadSchema>;

export interface LoginUsageInvoiceAccount {
  legacyUserId: number;
  username: string | null;
  successfulLoginCount: number;
  usageCount: number;
  usageDays: string[];
  amountCents: number;
}

@Injectable()
export class LoginAuditService {
  private readonly config = loadConfig();

  constructor(private readonly repository: LoginAuditRepository) {}

  async record(payload: unknown): Promise<{ accepted: true; duplicate: boolean }> {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for login audit."
      });
    }

    const parsed = this.parsePayload(payload);
    const occurredAt = normalizeDate(parsed.occurredAt);

    const result = await this.repository.recordEvent({
      eventKey: parsed.eventKey,
      legacyUserId: parsed.legacyUserId ?? null,
      identityUserId: parsed.identityUserId ?? null,
      username: parsed.username ?? null,
      eventType: parsed.eventType,
      success: parsed.success,
      occurredAt,
      ipAddress: normalizeIpAddress(parsed.ipAddress),
      ipAddressHash: hashMaybe(normalizeIpAddress(parsed.ipAddress), this.config.loginAudit.hashSalt),
      userAgentHash: hashMaybe(parsed.userAgent, this.config.loginAudit.hashSalt),
      source: parsed.source,
      traceId: parsed.traceId ?? null,
      metadata: sanitizeMetadata(parsed.metadata ?? {})
    });

    return { accepted: true, duplicate: result.duplicate };
  }

  async getUserAudit(legacyUserId: number, ipExposure: LoginAuditIpExposure = "full") {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for login audit."
      });
    }

    return this.repository.getUserAudit(legacyUserId, 20, ipExposure);
  }

  async createUsageInvoice(input: {
    accounts: Array<{ legacyUserId: number; username: string | null }>;
    from?: Date;
    to?: Date;
  }) {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for login audit."
      });
    }

    const accountsById = new Map(
      input.accounts
        .filter((account) => Number.isSafeInteger(account.legacyUserId) && account.legacyUserId > 0)
        .map((account) => [account.legacyUserId, account])
    );
    const events = await this.repository.listSuccessfulLoginEventsByLegacyUserIds([...accountsById.keys()], {
      from: input.from,
      to: input.to
    });
    const usagesByAccount = new Map<number, { successfulLoginCount: number; usageDays: Set<string> }>();
    for (const event of events) {
      const current = usagesByAccount.get(event.legacyUserId) ?? { successfulLoginCount: 0, usageDays: new Set<string>() };
      current.successfulLoginCount += 1;
      current.usageDays.add(calendarDay(event.occurredAt, this.config.loginAudit.billingTimezone));
      usagesByAccount.set(event.legacyUserId, current);
    }

    const accounts: LoginUsageInvoiceAccount[] = [...accountsById.values()]
      .map((account) => {
        const usage = usagesByAccount.get(account.legacyUserId) ?? { successfulLoginCount: 0, usageDays: new Set<string>() };
        const usageDays = [...usage.usageDays].sort();
        const usageCount = usageDays.length;
        return {
          legacyUserId: account.legacyUserId,
          username: account.username,
          successfulLoginCount: usage.successfulLoginCount,
          usageCount,
          usageDays,
          amountCents: usageCount * this.config.loginAudit.unitPriceCents
        };
      })
      .filter((account) => account.usageCount > 0)
      .sort((left, right) => left.username?.localeCompare(right.username ?? "") || left.legacyUserId - right.legacyUserId);
    const usageCount = accounts.reduce((total, account) => total + account.usageCount, 0);

    return {
      billingRule: "successful-login-per-account-calendar-day-v1",
      billingTimezone: this.config.loginAudit.billingTimezone,
      unitPriceCents: this.config.loginAudit.unitPriceCents,
      period: {
        from: input.from?.toISOString() ?? null,
        to: input.to?.toISOString() ?? null
      },
      accountCount: accountsById.size,
      accountsWithUsage: accounts.length,
      successfulLoginCount: events.length,
      usageCount,
      amountCents: usageCount * this.config.loginAudit.unitPriceCents,
      accounts
    };
  }

  private parsePayload(payload: unknown): LoginAuditPayload {
    const parsed = payloadSchema.safeParse(payload);
    if (!parsed.success) {
      throw new BadRequestException({
        code: "INVALID_LOGIN_AUDIT_EVENT",
        message: "Login audit event payload is invalid.",
        details: parsed.error.flatten()
      });
    }

    if (!parsed.data.legacyUserId && !parsed.data.identityUserId && !parsed.data.username) {
      throw new BadRequestException({
        code: "LOGIN_AUDIT_SUBJECT_REQUIRED",
        message: "At least one user identifier is required."
      });
    }

    return parsed.data;
  }
}

function normalizeDate(value: LoginAuditPayload["occurredAt"]): Date {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === "number") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }
  if (typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
  }

  return new Date();
}

function hashMaybe(value: string | null | undefined, salt: string): string | null {
  const normalized = value?.trim();
  if (!normalized) {
    return null;
  }

  return createHash("sha256").update(salt).update("\0").update(normalized).digest("hex");
}

function normalizeIpAddress(value: string | null | undefined): string | null {
  const candidate = value?.trim();
  if (!candidate) return null;
  const normalized = candidate.startsWith("::ffff:") ? candidate.slice("::ffff:".length) : candidate;
  return isIP(normalized) ? normalized.toLowerCase() : null;
}

function calendarDay(value: Date, timeZone: string): string {
  const formatter = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  });
  const parts = formatter.formatToParts(value);
  const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((item) => item.type === type)?.value;
  return `${part("year")}-${part("month")}-${part("day")}`;
}

export function sanitizeMetadata(value: Record<string, unknown>): Record<string, unknown> {
  return sanitizeObject(value, 0);
}

function sanitizeObject(value: Record<string, unknown>, depth: number): Record<string, unknown> {
  if (depth > 3) {
    return {};
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (isSensitiveKey(key)) {
      sanitized[key] = "[filtered]";
      continue;
    }
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      sanitized[key] = sanitizeObject(raw as Record<string, unknown>, depth + 1);
      continue;
    }
    if (Array.isArray(raw)) {
      sanitized[key] = raw.slice(0, 20).map((item) =>
        item && typeof item === "object" ? sanitizeObject(item as Record<string, unknown>, depth + 1) : item
      );
      continue;
    }

    sanitized[key] = raw;
  }

  return JSON.parse(JSON.stringify(sanitized));
}

function isSensitiveKey(key: string): boolean {
  return /(password|passwd|pwd|token|authorization|secret|credential|cookie|session)/i.test(key);
}
