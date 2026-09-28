import { BadRequestException } from "@nestjs/common";
import { z } from "zod";

const positiveInteger = z.string().regex(/^[1-9]\d*$/).transform(Number).refine(Number.isSafeInteger);
const timestamp = z.string().datetime({ offset: true }).transform((value) => new Date(value));
const querySchema = z.object({
  start_at: timestamp,
  end_at: timestamp,
  search: z.string().trim().max(255).optional(),
  role: z.enum(["root", "admin", "manager", "user", "other"]).optional(),
  page: positiveInteger.default("1"),
  pageSize: positiveInteger.refine((value) => value <= 100).default("20")
}).refine((query) => query.start_at < query.end_at, { message: "Invalid date range" })
  .refine((query) => Number.isSafeInteger((query.page - 1) * query.pageSize), { message: "Invalid page" });

export function parseOrganizationLoginQuery(query: Record<string, unknown>) {
  const result = querySchema.safeParse(query);
  if (!result.success) {
    throw new BadRequestException({ code: "INVALID_LOGIN_EVENTS_QUERY", message: "登录流水查询条件无效，请检查日期和分页参数" });
  }
  return result.data;
}

export function auditPrimaryRole(roles: readonly string[]): "root" | "admin" | "manager" | "user" | "other" {
  return (["root", "admin", "manager", "user"] as const).find((role) => roles.includes(role)) ?? "other";
}

export interface OrganizationLoginEventQuery {
  userIds: number[];
  startAt: Date;
  endAt: Date;
  page: number;
  pageSize: number;
}

export interface OrganizationLoginEvent {
  eventKey: string;
  userId: number;
  occurredAt: string;
  source: string;
}
