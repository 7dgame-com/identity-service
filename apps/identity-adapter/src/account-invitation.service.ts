import { randomBytes } from "node:crypto";
import { HttpException, Inject, Injectable, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { IdentityInvitation, InvitationIdentityRepository } from "./invitation-identity.repository.js";
import { InvitationLegacyRedisRepository } from "./invitation-legacy-redis.repository.js";
import { InvitationRecordRepository } from "./invitation-record.repository.js";
import { InvitationRedisReader, LegacyRedisInvitation } from "./invitation-redis.reader.js";
import { JwtIssuerService, VerifiedAccessToken } from "./jwt-issuer.service.js";

const createInvitationSchema = z.object({
  quota: z.union([z.number(), z.string()]).transform((value) => Number(value)),
  expiresIn: z
    .union([z.number(), z.string()])
    .optional()
    .transform((value) => (value === undefined || value === "" ? undefined : Number(value))),
  note: z.string().max(1024).optional().default("")
});

const deleteInvitationSchema = z.object({
  code: z.string().trim().min(1).max(64)
});

export class InvitationNativeFallbackRequiredError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "InvitationNativeFallbackRequiredError";
  }
}

@Injectable()
export class AccountInvitationService {
  private readonly config = loadConfig();

  constructor(
    @Inject(InvitationIdentityRepository)
    private readonly identityInvitations: InvitationIdentityRepository,
    @Inject(InvitationLegacyRedisRepository)
    private readonly legacyRedis: InvitationLegacyRedisRepository,
    @Inject(InvitationRedisReader)
    private readonly redisReader: InvitationRedisReader,
    @Inject(InvitationRecordRepository)
    private readonly invitationRecords: InvitationRecordRepository,
    @Inject(JwtIssuerService)
    private readonly jwtIssuer: JwtIssuerService
  ) {}

  isManagementNativeReady(): boolean {
    return (
      this.config.accountLifecycle.invitationManagementNativeEnabled &&
      this.identityInvitations.isConfigured() &&
      this.legacyRedis.isConfigured() &&
      this.redisReader.isConfigured()
    );
  }

  isCheckNativeReady(): boolean {
    return this.config.accountLifecycle.invitationCheckNativeEnabled && this.identityInvitations.isConfigured();
  }

  isRecordsNativeReady(): boolean {
    return this.config.accountLifecycle.invitationRecordsNativeEnabled && this.invitationRecords.isConfigured();
  }

  supports(path: string): boolean {
    return [
      "/v1/plugin-user/invitations",
      "/v1/plugin-user/create-invitation",
      "/v1/plugin-user/delete-invitation",
      "/v1/plugin-user/check-invitation",
      "/v1/plugin-user/invitation-records"
    ].includes(path);
  }

  isEnabledForPath(path: string): boolean {
    if (path === "/v1/plugin-user/check-invitation") {
      return this.config.accountLifecycle.invitationCheckNativeEnabled;
    }
    if (path === "/v1/plugin-user/invitation-records") {
      return this.config.accountLifecycle.invitationRecordsNativeEnabled;
    }

    return this.config.accountLifecycle.invitationManagementNativeEnabled;
  }

  async handle(
    path: string,
    payload: unknown,
    request: { authorization?: string | string[]; originalUrl?: string }
  ): Promise<{ status: number; body: unknown }> {
    if (path === "/v1/plugin-user/check-invitation") {
      return { status: 200, body: await this.check(request.originalUrl) };
    }
    if (path === "/v1/plugin-user/invitation-records") {
      this.assertRecordsReady();
      const claims = this.currentUser(request.authorization);
      this.assertCanManageInvitations(claims);

      return { status: 200, body: await this.records(request.originalUrl) };
    }

    this.assertManagementReady();
    const claims = this.currentUser(request.authorization);
    this.assertCanManageInvitations(claims);

    if (path === "/v1/plugin-user/invitations") {
      return { status: 200, body: await this.list() };
    }
    if (path === "/v1/plugin-user/create-invitation") {
      return { status: 200, body: await this.create(claims, payload) };
    }
    if (path === "/v1/plugin-user/delete-invitation") {
      return { status: 200, body: await this.delete(payload) };
    }

    throw new InvitationNativeFallbackRequiredError(`Native invitation path ${path} is not supported.`);
  }

  private async check(originalUrl: string | undefined) {
    this.assertCheckReady();
    const code = getQueryParam(originalUrl, "code")?.trim();
    if (!code) {
      return invalidInvitation("邀请码不存在或已过期");
    }

    const identityInvitation = (await this.identityInvitations.findByCodes([code]))[0] ?? null;
    if (this.redisReader.isConfigured()) {
      const redisInvitation = (await this.redisReader.scanInvitations(code)).invitations[0] ?? null;
      if (hasCheckMismatch(identityInvitation, redisInvitation)) {
        throw new InvitationNativeFallbackRequiredError("identity invitation check differs from legacy Redis");
      }
    }

    if (!identityInvitation || identityInvitation.status === "deleted") {
      return invalidInvitation("邀请码不存在或已过期");
    }
    if (identityInvitation.expiresAt <= Math.floor(Date.now() / 1000)) {
      return invalidInvitation("邀请码已过期");
    }
    if (identityInvitation.remaining <= 0) {
      return invalidInvitation("邀请名额已用完");
    }

    return {
      valid: true,
      remaining: identityInvitation.remaining,
      expiresAt: identityInvitation.expiresAt
    };
  }

  private async list() {
    const redisScan = await this.redisReader.scanInvitations();
    if (!redisScan.configured) {
      throw new ServiceUnavailableException({
        code: "LEGACY_INVITATION_REDIS_NOT_CONFIGURED",
        message: "Legacy invitation Redis is not configured."
      });
    }

    return redisScan.invitations.map(invitationResponseFromRedis).sort((a, b) => b.createdAt - a.createdAt);
  }

  private async records(originalUrl: string | undefined) {
    const code = getQueryParam(originalUrl, "code")?.trim() ?? "";
    const result = await this.invitationRecords.listByInviteCode(code);
    if (!result.configured) {
      throw new ServiceUnavailableException({
        code: "LEGACY_INVITATION_RECORDS_NOT_CONFIGURED",
        message: "Legacy invitation records database is not configured."
      });
    }

    return result.rows;
  }

  private async create(claims: VerifiedAccessToken, payload: unknown) {
    const parsed = parseBody(createInvitationSchema, payload);
    if (!Number.isInteger(parsed.quota) || parsed.quota < 1) {
      throw legacyError(400, 4001, "可注册人数必须为正整数");
    }
    const ttl = parsed.expiresIn && Number.isInteger(parsed.expiresIn) && parsed.expiresIn > 0 ? parsed.expiresIn : 7 * 24 * 60 * 60;
    const now = Math.floor(Date.now() / 1000);
    const invitation = {
      code: randomInviteCode(),
      quota: parsed.quota,
      remaining: parsed.quota,
      expiresAt: now + ttl,
      creatorId: claims.uid,
      creatorName: claims.username ?? "",
      note: parsed.note,
      createdAt: now
    };

    const created = await this.identityInvitations.create({
      inviteCode: invitation.code,
      quota: invitation.quota,
      remaining: invitation.remaining,
      expiresAt: invitation.expiresAt,
      creatorLegacyUserId: invitation.creatorId,
      creatorName: invitation.creatorName,
      note: invitation.note,
      legacyCreatedAt: invitation.createdAt,
      source: "identity-service-dual-write"
    });
    await this.legacyRedis.create(invitation);

    return {
      code: 0,
      data: invitationResponseFromIdentity(created)
    };
  }

  private async delete(payload: unknown) {
    const parsed = parseBody(deleteInvitationSchema, payload);
    if (!(await this.legacyRedis.exists(parsed.code))) {
      throw legacyError(404, 4004, "邀请码不存在或已过期");
    }

    await this.identityInvitations.markDeleted(parsed.code);
    await this.legacyRedis.delete(parsed.code);

    return {
      code: 0,
      message: "邀请已撤销"
    };
  }

  private assertManagementReady(): void {
    if (!this.config.accountLifecycle.invitationManagementNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "INVITATION_MANAGEMENT_NATIVE_DISABLED",
        message: "Native invitation management is disabled."
      });
    }
    if (!this.identityInvitations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_INVITATION_NATIVE",
        message: "Identity database is required for native invitation management."
      });
    }
    if (!this.legacyRedis.isConfigured() || !this.redisReader.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_INVITATION_REDIS_NOT_CONFIGURED",
        message: "Legacy invitation Redis is required for dual-write invitation management."
      });
    }
  }

  private assertCheckReady(): void {
    if (!this.config.accountLifecycle.invitationCheckNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "INVITATION_CHECK_NATIVE_DISABLED",
        message: "Native invitation check is disabled."
      });
    }
    if (!this.identityInvitations.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_DB_REQUIRED_FOR_INVITATION_CHECK_NATIVE",
        message: "Identity database is required for native invitation check."
      });
    }
  }

  private assertRecordsReady(): void {
    if (!this.config.accountLifecycle.invitationRecordsNativeEnabled) {
      throw new ServiceUnavailableException({
        code: "INVITATION_RECORDS_NATIVE_DISABLED",
        message: "Native invitation records is disabled."
      });
    }
    if (!this.invitationRecords.isConfigured()) {
      throw new ServiceUnavailableException({
        code: "LEGACY_INVITATION_RECORDS_NOT_CONFIGURED",
        message: "Legacy invitation records database is required for native invitation records."
      });
    }
  }

  private currentUser(authorization: string | string[] | undefined): VerifiedAccessToken {
    const token = bearerToken(authorization);
    if (!token) {
      throw unauthorized("用户未登录");
    }

    try {
      return this.jwtIssuer.verifyAccessToken(token);
    } catch {
      throw unauthorized("用户未登录");
    }
  }

  private assertCanManageInvitations(claims: VerifiedAccessToken): void {
    if (!claims.roles.some((role) => ["root", "admin", "manager"].includes(role))) {
      throw new HttpException(
        {
          code: 2003,
          message: "没有权限执行此操作"
        },
        403
      );
    }
  }
}

function invitationResponseFromRedis(invitation: LegacyRedisInvitation) {
  return {
    code: invitation.code,
    quota: invitation.quota ?? 0,
    remaining: invitation.remaining ?? 0,
    expiresAt: invitation.expiresAt ?? 0,
    creatorId: invitation.creatorId === null ? "" : String(invitation.creatorId),
    creatorName: invitation.creatorName ?? "",
    note: invitation.note ?? "",
    createdAt: invitation.createdAt ?? 0,
    status: statusFromFields(invitation.expiresAt, invitation.remaining)
  };
}

function invitationResponseFromIdentity(invitation: IdentityInvitation) {
  return {
    code: invitation.inviteCode,
    quota: invitation.quota,
    remaining: invitation.remaining,
    expiresAt: invitation.expiresAt,
    creatorId: invitation.creatorLegacyUserId ?? "",
    creatorName: invitation.creatorName ?? "",
    note: invitation.note ?? "",
    createdAt: invitation.legacyCreatedAt
  };
}

function hasCheckMismatch(identityInvitation: IdentityInvitation | null, redisInvitation: LegacyRedisInvitation | null): boolean {
  if (!identityInvitation && !redisInvitation) {
    return false;
  }
  if (!identityInvitation || !redisInvitation) {
    return true;
  }

  return (
    identityInvitation.remaining !== (redisInvitation.remaining ?? Number.NaN) ||
    identityInvitation.expiresAt !== (redisInvitation.expiresAt ?? Number.NaN) ||
    identityInvitation.status !== statusFromFields(redisInvitation.expiresAt, redisInvitation.remaining)
  );
}

function invalidInvitation(reason: string) {
  return {
    valid: false,
    reason
  };
}

function statusFromFields(expiresAt: number | null, remaining: number | null): string {
  const now = Math.floor(Date.now() / 1000);
  if (expiresAt !== null && expiresAt <= now) {
    return "expired";
  }
  if (remaining !== null && remaining <= 0) {
    return "used_up";
  }

  return "active";
}

function bearerToken(authorization: string | string[] | undefined): string | null {
  const header = Array.isArray(authorization) ? authorization[0] : authorization;
  if (!header?.startsWith("Bearer ")) {
    return null;
  }

  return header.slice("Bearer ".length).trim() || null;
}

function parseBody<T extends z.ZodTypeAny>(schema: T, payload: unknown): z.infer<T> {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new HttpException(
      {
        code: 4001,
        message: "请求参数验证失败",
        errors: parsed.error.flatten().fieldErrors
      },
      400
    );
  }

  return parsed.data;
}

function legacyError(status: number, code: number, message: string): HttpException {
  return new HttpException({ code, message }, status);
}

function unauthorized(message: string): UnauthorizedException {
  return new UnauthorizedException({
    code: 401,
    message
  });
}

function randomInviteCode(): string {
  return randomBytes(4).toString("hex");
}

function getQueryParam(originalUrl: string | undefined, name: string): string | null {
  const index = originalUrl?.indexOf("?") ?? -1;
  if (index < 0 || !originalUrl) {
    return null;
  }

  return new URLSearchParams(originalUrl.slice(index + 1)).get(name);
}
