import { createHash } from "node:crypto";
import { BadRequestException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { LoginAuditRepository } from "./login-audit.repository.js";

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
      ipAddressHash: hashMaybe(parsed.ipAddress, this.config.loginAudit.hashSalt),
      userAgentHash: hashMaybe(parsed.userAgent, this.config.loginAudit.hashSalt),
      source: parsed.source,
      traceId: parsed.traceId ?? null,
      metadata: sanitizeMetadata(parsed.metadata ?? {})
    });

    return { accepted: true, duplicate: result.duplicate };
  }

  async getUserAudit(legacyUserId: number) {
    if (!this.repository.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is not configured for login audit."
      });
    }

    return this.repository.getUserAudit(legacyUserId);
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
