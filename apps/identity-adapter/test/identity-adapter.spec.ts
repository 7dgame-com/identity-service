import "reflect-metadata";
import { generateKeyPairSync } from "node:crypto";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppModule } from "../src/app.module.js";
import { AccountEmailRepository } from "../src/account-email.repository.js";
import { AccountInvitationService } from "../src/account-invitation.service.js";
import { AccountLifecycleOperationRepository } from "../src/account-lifecycle-operation.repository.js";
import { AccountPasswordRepository } from "../src/account-password.repository.js";
import { AccountRegistrationRepository, NativeRegistrationError } from "../src/account-registration.repository.js";
import { EmailChangeTokenError, EmailChangeTokenRepository } from "../src/email-change-token.repository.js";
import { EmailDeliveryService } from "../src/email-delivery.service.js";
import { EmailVerificationChallengeError, EmailVerificationChallengeRepository } from "../src/email-verification-challenge.repository.js";
import { loadConfig } from "../src/config.js";
import { IdentitySessionRepository, InvalidRefreshTokenError } from "../src/identity-session.repository.js";
import { IdentityInvitation, InvitationIdentityRepository } from "../src/invitation-identity.repository.js";
import { InvitationImportService } from "../src/invitation-import.service.js";
import { InvitationLegacyRedisRepository } from "../src/invitation-legacy-redis.repository.js";
import { InvitationRecordRepository } from "../src/invitation-record.repository.js";
import { InvitationRedisReader, LegacyRedisInvitation } from "../src/invitation-redis.reader.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { LegacySessionRevocationService } from "../src/legacy-session-revocation.service.js";
import { LoginAuditRepository, PersistedLoginAuditEvent } from "../src/login-audit.repository.js";
import { PasswordResetChallengeError, PasswordResetChallengeRepository } from "../src/password-reset-challenge.repository.js";
import { sanitizeMetadata } from "../src/login-audit.service.js";
import { assertReadonlySql } from "../src/readonly-write.guard.js";
import { normalizeOtlpTraceEndpoint, startTelemetry } from "../src/telemetry.js";

class FakeLegacyIdentityReader {
  readonly passwordHash = bcrypt.hashSync("123456", 4);

  async health() {
    return "not_configured";
  }

  async diagnostics() {
    return {
      legacyDatabaseConfigured: false,
      tables: {
        user: false,
        user_info: false,
        auth_item: false,
        auth_assignment: false,
        organization: false,
        user_organization: false
      }
    };
  }

  async getUserById(id: number) {
    if (id === 25) {
      return {
        id: 25,
        username: "unverified",
        email: "unverified@example.com",
        status: 10,
        nickname: null,
        emailVerifiedAt: null,
        createdAt: 1558664856,
        updatedAt: 1763711034,
        userInfo: {},
        roles: ["user"],
        organizations: [],
        source: "legacy" as const
      };
    }

    if (id !== 24) {
      return null;
    }

    return {
      id: 24,
      username: "guanfei",
      email: "ogre3d@163.com",
      status: 10,
      nickname: "babamama",
      emailVerifiedAt: 1772210253,
      createdAt: 1558664856,
      updatedAt: 1763711034,
      userInfo: { locale: "zh-CN" },
      roles: ["admin"],
      organizations: [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }],
      source: "legacy" as const
    };
  }

  async getUserCredentialByUsername(username: string) {
    if (username === "unverified") {
      return {
        id: 25,
        username: "unverified",
        email: "unverified@example.com",
        status: 10,
        nickname: null,
        passwordHash: this.passwordHash
      };
    }

    if (username !== "guanfei") {
      return null;
    }

    return {
      id: 24,
      username: "guanfei",
      email: "ogre3d@163.com",
      status: 10,
      nickname: "babamama",
      passwordHash: this.passwordHash
    };
  }

  async listRoles() {
    return [{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }];
  }

  async listOrganizations() {
    return [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }];
  }
}

class FakeIdentitySessionRepository {
  readonly sessions = new Map<
    string,
    {
      id: number;
      sessionId: string;
      legacyUserId: number;
      username: string | null;
      expiresAt: Date;
      revokedAt: Date | null;
    }
  >();
  nextId = 1;

  isConfigured() {
    return true;
  }

  async issue(input: { legacyUserId: number; username: string | null; sessionId: string; expiresAt: Date }) {
    const refreshToken = `refresh-${this.nextId}`;
    const session = {
      id: this.nextId,
      sessionId: input.sessionId,
      legacyUserId: input.legacyUserId,
      username: input.username,
      expiresAt: input.expiresAt,
      revokedAt: null
    };
    this.nextId += 1;
    this.sessions.set(refreshToken, session);

    return {
      refreshToken,
      refreshTokenHash: `hash-${refreshToken}`,
      sessionId: session.sessionId,
      legacyUserId: session.legacyUserId,
      username: session.username,
      expiresAt: session.expiresAt
    };
  }

  async findValidSession(refreshToken: string) {
    const session = this.sessions.get(refreshToken);
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new InvalidRefreshTokenError();
    }

    return {
      ...session,
      refreshTokenHash: `hash-${refreshToken}`
    };
  }

  async rotate(
    refreshToken: string,
    input: { legacyUserId: number; username: string | null; sessionId: string; expiresAt: Date }
  ) {
    const current = await this.findValidSession(refreshToken);
    const stored = this.sessions.get(refreshToken);
    if (stored) {
      stored.revokedAt = new Date();
    }

    expect(current.legacyUserId).toBe(input.legacyUserId);
    return this.issue(input);
  }

  async revoke(refreshToken: string | null | undefined) {
    if (!refreshToken) {
      return true;
    }

    const session = this.sessions.get(refreshToken);
    if (session) {
      session.revokedAt = session.revokedAt ?? new Date();
    }

    return true;
  }

  async revokeUserSessions(legacyUserId: number) {
    let revoked = 0;
    for (const session of this.sessions.values()) {
      if (session.legacyUserId === legacyUserId && !session.revokedAt) {
        session.revokedAt = new Date();
        revoked += 1;
      }
    }

    return revoked;
  }
}

class FakeLegacySessionRevocationService {
  configured = true;
  fail = false;
  readonly calls: Array<{ legacyUserId: number; reason: "password.change" | "password.reset" }> = [];

  isConfigured() {
    return this.configured;
  }

  async revokeUserSessions(legacyUserId: number, reason: "password.change" | "password.reset") {
    this.calls.push({ legacyUserId, reason });
    if (this.fail) {
      return {
        attempted: true,
        ok: false,
        error: "legacy unavailable"
      };
    }

    return {
      attempted: true,
      ok: true,
      revoked: 2
    };
  }
}

class FakeAccountRegistrationRepository {
  configured = true;
  nextUserId = 1000;
  readonly users = new Map<string, { id: number; username: string; email: string | null }>();
  readonly wechatBindings = new Map<string, number | null>([
    ["wechat-token", null],
    ["registered-wechat-token", 24]
  ]);

  isConfigured() {
    return this.configured;
  }

  async register(input: { username: string; password: string; email?: string | null }) {
    return this.createUser(input.username, input.email ?? null);
  }

  async registerWechat(input: { username: string; password: string; email?: string | null; wechatToken: string }) {
    if (!this.wechatBindings.has(input.wechatToken)) {
      throw new NativeRegistrationError(400, "no wechat");
    }
    const currentUserId = this.wechatBindings.get(input.wechatToken);
    if (currentUserId) {
      throw new NativeRegistrationError(400, `already registered,${currentUserId}`);
    }

    const user = this.createUser(input.username, input.email ?? null);
    this.wechatBindings.set(input.wechatToken, user.id);

    return user;
  }

  private createUser(username: string, email: string | null) {
    if (this.users.has(username)) {
      throw new NativeRegistrationError(400, {
        username: [`Username "${username}" has already been taken.`],
        message: "username already exists"
      });
    }

    const id = this.nextUserId;
    this.nextUserId += 1;
    const user = {
      id,
      username,
      email,
      status: 10,
      nickname: null,
      emailVerifiedAt: null,
      createdAt: 1770451200,
      updatedAt: 1770451200,
      userInfo: null,
      roles: ["user"],
      organizations: [],
      source: "legacy" as const
    };
    this.users.set(username, { id, username, email });

    return user;
  }
}

class FakeAccountLifecycleOperationRepository {
  configured = true;
  readonly operations = new Map<
    string,
    {
      status: "pending" | "completed" | "failed";
      operationType: string;
      username: string | null;
      email: string | null;
      user?: Awaited<ReturnType<FakeAccountRegistrationRepository["register"]>>;
      errorCode?: string;
    }
  >();

  isConfigured() {
    return this.configured;
  }

  async findCompleted(operationKey: string) {
    const operation = this.operations.get(operationKey);
    return operation?.status === "completed" ? (operation.user ?? null) : null;
  }

  async begin(input: { operationKey: string; operationType: string; username: string | null; email: string | null }) {
    const current = this.operations.get(input.operationKey);
    if (!current || current.status === "failed") {
      this.operations.set(input.operationKey, {
        status: "pending",
        operationType: input.operationType,
        username: input.username,
        email: input.email
      });
      return;
    }

    throw new Error("operation already pending");
  }

  async complete(input: {
    operationKey: string;
    operationType: string;
    username: string | null;
    email: string | null;
    user: Awaited<ReturnType<FakeAccountRegistrationRepository["register"]>>;
  }) {
    this.operations.set(input.operationKey, {
      status: "completed",
      operationType: input.operationType,
      username: input.username,
      email: input.email,
      user: input.user
    });
  }

  async fail(input: { operationKey: string; operationType: string; username: string | null; email: string | null; errorCode: string }) {
    this.operations.set(input.operationKey, {
      status: "failed",
      operationType: input.operationType,
      username: input.username,
      email: input.email,
      errorCode: input.errorCode
    });
  }
}

class FakeAccountPasswordRepository {
  configured = true;
  readonly users = new Map<
    number,
    {
      id: number;
      username: string | null;
      email: string | null;
      status: number;
      passwordHash: string | null;
      emailVerifiedAt: number | null;
      changeCount: number;
    }
  >([
    [
      24,
      {
        id: 24,
        username: "guanfei",
        email: "ogre3d@163.com",
        status: 10,
        passwordHash: bcrypt.hashSync("123456", 4),
        emailVerifiedAt: 1772210253,
        changeCount: 0
      }
    ],
    [
      25,
      {
        id: 25,
        username: "unverified",
        email: "unverified@example.com",
        status: 10,
        passwordHash: bcrypt.hashSync("123456", 4),
        emailVerifiedAt: null,
        changeCount: 0
      }
    ]
  ]);

  isConfigured() {
    return this.configured;
  }

  async getCredentialById(userId: number) {
    return this.users.get(userId) ?? null;
  }

  async getCredentialByEmail(email: string) {
    const normalized = email.trim().toLowerCase();
    return [...this.users.values()].find((user) => user.email === normalized) ?? null;
  }

  async verifyPassword(password: string, passwordHash: string | null) {
    if (!passwordHash) {
      return false;
    }

    return bcrypt.compare(password, passwordHash);
  }

  async changePassword(user: { id: number; username: string | null; email: string | null; status: number; emailVerifiedAt: number | null }, newPassword: string) {
    const current = this.users.get(user.id);
    if (!current) {
      throw new Error("missing fake user");
    }

    current.passwordHash = bcrypt.hashSync(newPassword, 4);
    current.changeCount += 1;

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      status: user.status,
      nickname: null,
      emailVerifiedAt: user.emailVerifiedAt,
      createdAt: null,
      updatedAt: 1770451200,
      userInfo: null,
      roles: ["user"],
      organizations: [],
      source: "legacy" as const
    };
  }
}

class FakeAccountEmailRepository {
  configured = true;
  readonly users = new Map<
    number,
    {
      id: number;
      username: string | null;
      email: string | null;
      status: number;
      emailVerifiedAt: number | null;
    }
  >([
    [
      24,
      {
        id: 24,
        username: "guanfei",
        email: "ogre3d@163.com",
        status: 10,
        emailVerifiedAt: 1772210253
      }
    ],
    [
      25,
      {
        id: 25,
        username: "unverified",
        email: "unverified@example.com",
        status: 10,
        emailVerifiedAt: null
      }
    ]
  ]);

  isConfigured() {
    return this.configured;
  }

  async getUserById(userId: number) {
    return this.users.get(userId) ?? null;
  }

  async isEmailBoundByOther(email: string, legacyUserId: number) {
    const normalized = email.trim().toLowerCase();
    return [...this.users.values()].some((user) => user.id !== legacyUserId && user.email === normalized);
  }

  async bindVerifiedEmail(legacyUserId: number, email: string, verifiedAt: number) {
    const current = this.users.get(legacyUserId);
    if (!current) {
      throw new Error("missing fake email user");
    }
    current.email = email.trim().toLowerCase();
    current.emailVerifiedAt = verifiedAt;

    return current;
  }

  async unbindEmail(legacyUserId: number, updatedAt: number) {
    const current = this.users.get(legacyUserId);
    if (!current) {
      throw new Error("missing fake email user");
    }
    current.email = null;
    current.emailVerifiedAt = null;
    void updatedAt;

    return current;
  }
}

class FakeEmailDeliveryService {
  configured = true;
  readonly sent: Array<{ email: string; code: string; locale?: string }> = [];

  isConfigured() {
    return this.configured;
  }

  async sendPasswordResetCode(input: { email: string; code: string; locale?: string }) {
    if (!this.configured) {
      throw new Error("email not configured");
    }

    this.sent.push({
      email: input.email,
      code: input.code,
      locale: input.locale
    });
  }

  async sendEmailVerificationCode(input: { email: string; code: string; locale?: string }) {
    if (!this.configured) {
      throw new Error("email not configured");
    }

    this.sent.push({
      email: input.email,
      code: input.code,
      locale: input.locale
    });
  }
}

class FakeEmailChangeTokenRepository {
  configured = true;
  token = "change-token-123";
  nextId = 1;
  readonly tokens = new Map<
    number,
    {
      id: number;
      tokenKey: string;
      legacyUserId: number;
      token: string;
      expiresAt: Date;
      consumedAt: Date | null;
      createdAt: Date;
    }
  >();

  isConfigured() {
    return this.configured;
  }

  async createToken(legacyUserId: number) {
    const record = {
      id: this.nextId,
      tokenKey: `email-change-token-${this.nextId}`,
      legacyUserId,
      token: this.token,
      tokenHash: `hash-${this.token}`,
      expiresAt: new Date(Date.now() + 600_000),
      consumedAt: null,
      createdAt: new Date()
    };
    this.nextId += 1;
    this.tokens.set(legacyUserId, record);

    return {
      token: this.token,
      expiresIn: 600,
      record
    };
  }

  async verifyToken(legacyUserId: number, token: string | undefined) {
    const record = this.tokens.get(legacyUserId);
    if (!token) {
      throw new EmailChangeTokenError(400, "INVALID_CODE", "改绑邮箱需先完成旧邮箱验证");
    }
    if (!record || record.consumedAt || record.expiresAt.getTime() <= Date.now() || record.token !== token) {
      throw new EmailChangeTokenError(400, "INVALID_CODE", "改绑确认已失效，请重新验证旧邮箱");
    }

    return record;
  }

  async consume(tokenKey: string) {
    for (const token of this.tokens.values()) {
      if (token.tokenKey === tokenKey) {
        token.consumedAt = token.consumedAt ?? new Date();
      }
    }
  }
}

class FakePasswordResetChallengeRepository {
  configured = true;
  readonly challenges = new Map<
    string,
    {
      id: number;
      challengeKey: string;
      legacyUserId: number;
      email: string;
      code: string;
      attempts: number;
      expiresAt: Date;
      lockedUntil: Date | null;
      consumedAt: Date | null;
      createdAt: Date;
    }
  >();
  nextId = 1;
  code = "123456";
  rateLimited = false;

  isConfigured() {
    return this.configured;
  }

  async createChallenge(input: { email: string; legacyUserId: number }) {
    if (this.rateLimited) {
      throw new PasswordResetChallengeError(429, "RATE_LIMIT_EXCEEDED", "请求过于频繁，请 60 秒后再试", 60);
    }

    const email = input.email.trim().toLowerCase();
    const challenge = {
      id: this.nextId,
      challengeKey: `challenge-${this.nextId}`,
      legacyUserId: input.legacyUserId,
      email,
      code: this.code,
      codeHash: `hash-${this.code}`,
      attempts: 0,
      expiresAt: new Date(Date.now() + 900_000),
      lockedUntil: null,
      consumedAt: null,
      createdAt: new Date()
    };
    this.nextId += 1;
    this.challenges.set(email, challenge);

    return { code: this.code, challenge };
  }

  async verifyCode(email: string, code: string) {
    const challenge = this.challenges.get(email.trim().toLowerCase());
    if (!challenge || challenge.consumedAt) {
      throw new PasswordResetChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
    }
    if (challenge.lockedUntil && challenge.lockedUntil.getTime() > Date.now()) {
      throw new PasswordResetChallengeError(429, "ACCOUNT_LOCKED", "验证失败次数过多，账户已被锁定，请 900 秒后再试", 900);
    }
    if (challenge.code !== code) {
      challenge.attempts += 1;
      if (challenge.attempts >= 5) {
        challenge.lockedUntil = new Date(Date.now() + 900_000);
      }
      throw new PasswordResetChallengeError(400, "INVALID_CODE", "验证码不正确");
    }

    return challenge;
  }

  async consume(challengeKey: string) {
    for (const challenge of this.challenges.values()) {
      if (challenge.challengeKey === challengeKey) {
        challenge.consumedAt = challenge.consumedAt ?? new Date();
      }
    }
  }
}

class FakeEmailVerificationChallengeRepository {
  configured = true;
  readonly challenges = new Map<
    string,
    {
      id: number;
      challengeKey: string;
      legacyUserId: number;
      email: string;
      code: string;
      attempts: number;
      expiresAt: Date;
      lockedUntil: Date | null;
      consumedAt: Date | null;
      createdAt: Date;
    }
  >();
  nextId = 1;
  code = "654321";
  rateLimited = false;

  isConfigured() {
    return this.configured;
  }

  async createChallenge(input: { email: string; legacyUserId: number }) {
    if (this.rateLimited) {
      throw new EmailVerificationChallengeError(429, "RATE_LIMIT_EXCEEDED", "请求过于频繁，请 60 秒后再试", 60);
    }

    const email = input.email.trim().toLowerCase();
    const challenge = {
      id: this.nextId,
      challengeKey: `email-challenge-${this.nextId}`,
      legacyUserId: input.legacyUserId,
      email,
      code: this.code,
      codeHash: `hash-${this.code}`,
      attempts: 0,
      expiresAt: new Date(Date.now() + 900_000),
      lockedUntil: null,
      consumedAt: null,
      createdAt: new Date()
    };
    this.nextId += 1;
    this.challenges.set(email, challenge);

    return { code: this.code, challenge };
  }

  async verifyCode(email: string, code: string) {
    const challenge = this.challenges.get(email.trim().toLowerCase());
    if (!challenge || challenge.consumedAt) {
      throw new EmailVerificationChallengeError(400, "INVALID_CODE", "验证码不存在或已过期");
    }
    if (challenge.lockedUntil && challenge.lockedUntil.getTime() > Date.now()) {
      throw new EmailVerificationChallengeError(429, "ACCOUNT_LOCKED", "验证失败次数过多，账户已被锁定，请 900 秒后再试", 900);
    }
    if (challenge.code !== code) {
      challenge.attempts += 1;
      if (challenge.attempts >= 5) {
        challenge.lockedUntil = new Date(Date.now() + 900_000);
      }
      throw new EmailVerificationChallengeError(400, "INVALID_CODE", "验证码不正确");
    }

    return challenge;
  }

  async consume(challengeKey: string) {
    for (const challenge of this.challenges.values()) {
      if (challenge.challengeKey === challengeKey) {
        challenge.consumedAt = challenge.consumedAt ?? new Date();
      }
    }
  }

  async getCooldown(email: string) {
    const challenge = this.challenges.get(email.trim().toLowerCase());
    if (!challenge) {
      return {
        canSend: true,
        retryAfter: 0,
        limitSeconds: 60
      };
    }

    const retryAfter = Math.max(0, Math.ceil((challenge.createdAt.getTime() + 60_000 - Date.now()) / 1000));
    return {
      canSend: retryAfter === 0,
      retryAfter,
      limitSeconds: 60
    };
  }
}

class FakeLoginAuditRepository {
  readonly events = new Map<string, PersistedLoginAuditEvent>();
  readonly stats = new Map<number, { loginCount: number; failedLoginCount: number; lastLoginAt: string | null }>();

  isConfigured() {
    return true;
  }

  async recordEvent(event: PersistedLoginAuditEvent) {
    if (this.events.has(event.eventKey)) {
      return { duplicate: true };
    }

    this.events.set(event.eventKey, event);
    if (event.legacyUserId) {
      const current = this.stats.get(event.legacyUserId) ?? {
        loginCount: 0,
        failedLoginCount: 0,
        lastLoginAt: null
      };
      if (event.success) {
        current.loginCount += 1;
        current.lastLoginAt = event.occurredAt.toISOString();
      } else {
        current.failedLoginCount += 1;
      }
      this.stats.set(event.legacyUserId, current);
    }

    return { duplicate: false };
  }

  async getUserAudit(legacyUserId: number) {
    const stats = this.stats.get(legacyUserId);

    return {
      stats: stats
        ? {
            legacyUserId,
            identityUserId: null,
            username: "guanfei",
            loginCount: stats.loginCount,
            failedLoginCount: stats.failedLoginCount,
            lastLoginAt: stats.lastLoginAt,
            lastFailedLoginAt: null,
            updatedAt: stats.lastLoginAt
          }
        : null,
      recentEvents: [...this.events.values()]
        .filter((event) => event.legacyUserId === legacyUserId)
        .map((event) => ({
          eventKey: event.eventKey,
          eventType: event.eventType,
          success: event.success,
          occurredAt: event.occurredAt.toISOString(),
          source: event.source,
          traceId: event.traceId,
          metadata: event.metadata
        }))
    };
  }
}

class FakeInvitationRedisReader {
  readonly calls: Array<string | null> = [];
  configured = true;
  invitations: LegacyRedisInvitation[] = [
    {
      code: "abc123",
      key: "invite:abc123",
      quota: 2,
      remaining: 1,
      expiresAt: 1770451200,
      creatorId: 24,
      creatorName: "guanfei",
      note: "dev",
      createdAt: 1770364800,
      ttl: 600,
      raw: {
        quota: "2",
        remaining: "1",
        expiresAt: "1770451200",
        creatorId: "24",
        creatorName: "guanfei",
        note: "dev",
        createdAt: "1770364800"
      }
    }
  ];

  isConfigured() {
    return this.configured;
  }

  async scanInvitations(code?: string | null) {
    this.calls.push(code ?? null);
    return {
      configured: this.configured,
      scannedKeys: this.configured ? this.invitations.length : 0,
      truncated: false,
      invitations: this.configured ? this.invitations.filter((invite) => !code || invite.code === code) : []
    };
  }
}

class FakeInvitationRecordRepository {
  configured = true;
  rows = [
    {
      id: 2,
      invite_code: "abc123",
      inviter_id: 24,
      invitee_id: 26,
      created_at: 1770365000,
      username: "newer-user",
      email: "newer@example.com"
    },
    {
      id: 1,
      invite_code: "abc123",
      inviter_id: 24,
      invitee_id: 25,
      created_at: 1770364900,
      username: "older-user",
      email: "older@example.com"
    }
  ];
  byCode = [
    {
      inviteCode: "abc123",
      recordCount: 3,
      firstCreatedAt: 1770364900,
      lastCreatedAt: 1770365000
    },
    {
      inviteCode: "ghost",
      recordCount: 1,
      firstCreatedAt: 1770365100,
      lastCreatedAt: 1770365100
    }
  ];

  isConfigured() {
    return this.configured;
  }

  async getStats(inviteCode?: string | null) {
    const byCode = this.configured ? this.byCode.filter((record) => !inviteCode || record.inviteCode === inviteCode) : [];
    return {
      configured: this.configured,
      totalRecords: byCode.reduce((sum, record) => sum + record.recordCount, 0),
      byCode
    };
  }

  async listByInviteCode(inviteCode?: string | null) {
    return {
      configured: this.configured,
      rows: this.configured ? this.rows.filter((record) => record.invite_code === inviteCode) : []
    };
  }
}

class FakeInvitationIdentityRepository {
  configured = true;
  readonly rows = new Map<string, IdentityInvitation>();
  readonly upserted: LegacyRedisInvitation[][] = [];

  isConfigured() {
    return this.configured;
  }

  async findByCodes(codes: string[]) {
    return codes.map((code) => this.rows.get(code)).filter((row): row is IdentityInvitation => Boolean(row));
  }

  async listActive() {
    return [...this.rows.values()].filter((row) => row.status !== "deleted");
  }

  async create(input: {
    inviteCode: string;
    quota: number;
    remaining: number;
    expiresAt: number;
    creatorLegacyUserId: number;
    creatorName: string;
    note: string;
    legacyCreatedAt: number;
    source: string;
  }) {
    const row: IdentityInvitation = {
      inviteCode: input.inviteCode,
      quota: input.quota,
      remaining: input.remaining,
      expiresAt: input.expiresAt,
      creatorLegacyUserId: input.creatorLegacyUserId,
      creatorName: input.creatorName,
      note: input.note,
      legacyCreatedAt: input.legacyCreatedAt,
      status: "active",
      source: input.source,
      importedAt: new Date(),
      lastSeenAt: new Date()
    };
    this.rows.set(input.inviteCode, row);

    return row;
  }

  async markDeleted(inviteCode: string) {
    const row = this.rows.get(inviteCode);
    if (row) {
      row.status = "deleted";
      return true;
    }

    return false;
  }

  async upsertImported(invitations: LegacyRedisInvitation[]) {
    this.upserted.push(invitations);
    for (const invitation of invitations) {
      this.rows.set(invitation.code, {
        inviteCode: invitation.code,
        quota: invitation.quota ?? 0,
        remaining: invitation.remaining ?? 0,
        expiresAt: invitation.expiresAt ?? 0,
        creatorLegacyUserId: invitation.creatorId,
        creatorName: invitation.creatorName,
        note: invitation.note,
        legacyCreatedAt: invitation.createdAt ?? 0,
        status: "active",
        source: "legacy-redis",
        importedAt: new Date(),
        lastSeenAt: new Date()
      });
    }

    return invitations.length;
  }
}

class FakeInvitationLegacyRedisRepository {
  configured = true;
  readonly rows = new Map<string, unknown>();
  readonly created: Array<{
    code: string;
    quota: number;
    remaining: number;
    expiresAt: number;
    creatorId: number;
    creatorName: string;
    note: string;
    createdAt: number;
  }> = [];
  readonly deleted: string[] = [];

  isConfigured() {
    return this.configured;
  }

  async create(input: {
    code: string;
    quota: number;
    remaining: number;
    expiresAt: number;
    creatorId: number;
    creatorName: string;
    note: string;
    createdAt: number;
  }) {
    this.created.push(input);
    this.rows.set(input.code, input);
  }

  async exists(code: string) {
    return this.rows.has(code);
  }

  async delete(code: string) {
    this.deleted.push(code);
    return this.rows.delete(code);
  }
}

describe("identity-adapter readonly API", () => {
  let app: INestApplication;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app.close();
  });

  it("returns health in readonly mode", async () => {
    const response = await request(app.getHttpServer()).get("/health").expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      mode: "readonly",
      dependencies: {
        legacyDatabase: "not_configured"
      }
    });
  });

  it("returns safe empty JWKS by default", async () => {
    const response = await request(app.getHttpServer()).get("/jwks.json").expect(200);

    expect(response.body).toEqual({ keys: [] });
  });

  it("returns readonly legacy user details", async () => {
    const response = await request(app.getHttpServer()).get("/admin/users/24").expect(200);

    expect(response.body.data).toMatchObject({
      id: 24,
      username: "guanfei",
      roles: ["admin"],
      organizations: [{ name: "test-university", title: "测试大学" }],
      source: "legacy"
    });
  });

  it("returns roles and organizations", async () => {
    const roles = await request(app.getHttpServer()).get("/admin/roles").expect(200);
    const organizations = await request(app.getHttpServer()).get("/admin/organizations").expect(200);

    expect(roles.body.data).toEqual([{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }]);
    expect(organizations.body.data).toEqual([
      { id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }
    ]);
  });

  it("does not implement token introspection in phase 3", async () => {
    await request(app.getHttpServer())
      .get("/userinfo")
      .set("Authorization", "Bearer legacy-token")
      .expect(501);
  });

  it("blocks write-like SQL statements", () => {
    expect(() => assertReadonlySql("SELECT * FROM user")).not.toThrow();
    expect(() => assertReadonlySql("UPDATE user SET status = 0")).toThrow(/blocked write-like SQL/);
  });

  it("loads optional OpenTelemetry settings safely", () => {
    const config = loadConfig({
      OTEL_SERVICE_NAME: "identity-adapter-test",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
      OTEL_EXPORTER_OTLP_TRACES_HEADERS: "tenant=dev,token=a=b"
    });

    expect(config.otel).toEqual({
      serviceName: "identity-adapter-test",
      exporterOtlpEndpoint: "http://collector:4318",
      exporterOtlpHeaders: "tenant=dev,token=a=b"
    });
    expect(normalizeOtlpTraceEndpoint(config.otel.exporterOtlpEndpoint!)).toBe("http://collector:4318/v1/traces");
  });

  it("keeps telemetry disabled unless an OTLP endpoint is configured", () => {
    const config = loadConfig({});

    expect(startTelemetry(config, {})).toEqual({ enabled: false, reason: "not_configured" });
  });

  it("keeps login audit disabled by default", async () => {
    await request(app.getHttpServer())
      .post("/internal/login-events")
      .send({
        eventKey: "legacy-login:24:test-disabled",
        legacyUserId: 24,
        username: "guanfei"
      })
      .expect(404);
  });

  it("keeps token issuance disabled by default", async () => {
    await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(404);
  });

  it("keeps legacy session revocation compensation as a no-op by default", async () => {
    delete process.env.IDENTITY_LEGACY_SESSION_REVOKE_ENABLED;
    delete process.env.IDENTITY_LEGACY_SESSION_REVOKE_URL;
    delete process.env.IDENTITY_LEGACY_SESSION_REVOKE_TOKEN;
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const service = new LegacySessionRevocationService();
    const result = await service.revokeUserSessions(24, "password.change");

    expect(result).toEqual({ attempted: false, ok: true });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps account lifecycle disabled by default", async () => {
    const readiness = await request(app.getHttpServer()).get("/internal/account-lifecycle/readiness").expect(200);

    expect(readiness.body.data).toMatchObject({
      enabled: false,
      mode: "disabled",
      legacyProxyConfigured: false,
      scopes: {
        register: false,
        password: false,
        email: false,
        invitation: false
      }
    });

    await request(app.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "wechat-token", username: "new-user", password: "123456" })
      .expect(404);
  });
});

describe("identity-adapter account lifecycle compatibility API", () => {
  let app: INestApplication | null = null;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "legacy-proxy";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_TIMEOUT_MS = "5000";
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("keeps individual scopes disabled even when the global lifecycle flag is enabled", async () => {
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await request(app.getHttpServer())
      .post("/v1/password/request-reset")
      .send({ email: "user@example.com" })
      .expect(404);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("proxies enabled register endpoints without changing status or response shape", async () => {
    process.env.IDENTITY_ACCOUNT_REGISTER_ENABLED = "true";
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          success: true,
          message: "register",
          uid: 42,
          token: {
            accessToken: "legacy-access-token",
            refreshToken: "legacy-refresh-token"
          }
        }),
        {
          status: 201,
          headers: { "Content-Type": "application/json" }
        }
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/wechat/register")
      .set("Authorization", "Bearer existing-token")
      .set("X-Forwarded-For", "10.0.0.2")
      .set("User-Agent", "Vitest")
      .send({ token: "wechat-token", username: "new-user", password: "123456" })
      .expect(201);

    expect(response.body).toMatchObject({
      success: true,
      message: "register",
      uid: 42,
      token: {
        accessToken: "legacy-access-token",
        refreshToken: "legacy-refresh-token"
      }
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/wechat/register");
    const headers = init.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer existing-token");
    expect(headers.get("X-Forwarded-For")).toBe("10.0.0.2");
    expect(headers.get("User-Agent")).toBe("Vitest");
    expect(headers.get("X-Identity-Lifecycle-Proxy")).toBe("1");
    expect(JSON.parse(String(init.body))).toEqual({
      token: "wechat-token",
      username: "new-user",
      password: "123456"
    });
  });

  it("preserves query strings for invitation compatibility endpoints", async () => {
    process.env.IDENTITY_ACCOUNT_INVITATION_ENABLED = "true";
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ valid: true, remaining: 2 }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/check-invitation?code=abc123")
      .expect(200);

    expect(response.body).toEqual({ valid: true, remaining: 2 });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/plugin-user/check-invitation?code=abc123");
    expect(init.body).toBeUndefined();
  });
});

describe("identity-adapter invitation diagnostics API", () => {
  let app: INestApplication | null = null;
  let redisReader: FakeInvitationRedisReader;
  let recordRepository: FakeInvitationRecordRepository;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED = "true";
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";

    redisReader = new FakeInvitationRedisReader();
    recordRepository = new FakeInvitationRecordRepository();
    app = await createInvitationDiagnosticsTestApp(redisReader, recordRepository);
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("keeps invitation diagnostics disabled by default", async () => {
    process.env.IDENTITY_ACCOUNT_INVITATION_DIAGNOSTICS_ENABLED = "false";
    await app?.close();
    app = await createInvitationDiagnosticsTestApp(redisReader, recordRepository);

    await request(app.getHttpServer())
      .get("/internal/account-lifecycle/invitations/diagnostics")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(404);

    expect(redisReader.calls).toHaveLength(0);
  });

  it("requires the internal service token", async () => {
    await request(app!.getHttpServer())
      .get("/internal/account-lifecycle/invitations/diagnostics")
      .expect(401);
  });

  it("reports legacy Redis invitation data and MySQL invitation records for reconciliation", async () => {
    const response = await request(app!.getHttpServer())
      .get("/internal/account-lifecycle/invitations/diagnostics")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      capability: "invitation-diagnostics",
      data: {
        sources: {
          legacyRedisConfigured: true,
          legacyDatabaseConfigured: true
        },
        redis: {
          scannedKeys: 1,
          invitations: [
            {
              code: "abc123",
              quota: 2,
              remaining: 1
            }
          ]
        },
        records: {
          totalRecords: 4
        },
        consistency: {
          checked: true
        }
      }
    });
    expect(response.body.data.consistency.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "abc123",
          type: "record_count_exceeds_used_quota",
          severity: "warning"
        }),
        expect.objectContaining({
          code: "ghost",
          type: "record_without_redis_invite",
          severity: "warning"
        })
      ])
    );
  });

  it("supports code-filtered diagnostics before a scoped rollout", async () => {
    const response = await request(app!.getHttpServer())
      .get("/internal/account-lifecycle/invitations/diagnostics?code=abc123")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(redisReader.calls).toEqual(["abc123"]);
    expect(response.body.data.filter).toEqual({ code: "abc123" });
    expect(response.body.data.records.totalRecords).toBe(3);
    expect(response.body.data.consistency.issues).toEqual([
      expect.objectContaining({
        code: "abc123",
        type: "record_count_exceeds_used_quota"
      })
    ]);
  });

  it("does not claim reconciliation when a legacy source is not configured", async () => {
    redisReader.configured = false;

    const response = await request(app!.getHttpServer())
      .get("/internal/account-lifecycle/invitations/diagnostics")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(response.body.data.consistency).toMatchObject({
      checked: false,
      issues: [
        {
          code: "*",
          type: "legacy_redis_not_configured",
          severity: "warning"
        }
      ]
    });
  });
});

describe("identity-adapter invitation import planner", () => {
  it("builds a dry-run plan without writing identity invitations", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const redisReader = new FakeInvitationRedisReader();
    redisReader.invitations = [
      legacyInvite("new-code", { expiresAt: future }),
      legacyInvite("existing-update", { remaining: 1, expiresAt: future }),
      legacyInvite("existing-same", { expiresAt: future }),
      legacyInvite("broken", { quota: null, expiresAt: future })
    ];
    const repository = new FakeInvitationIdentityRepository();
    repository.rows.set("existing-update", identityInvite("existing-update", { remaining: 2, expiresAt: future }));
    repository.rows.set("existing-same", identityInvite("existing-same", { expiresAt: future }));
    const importer = new InvitationImportService(
      redisReader as unknown as InvitationRedisReader,
      repository as unknown as InvitationIdentityRepository
    );

    const plan = await importer.plan();

    expect(plan.dryRun).toBe(true);
    expect(plan.summary).toEqual({
      create: 1,
      update: 1,
      unchanged: 1,
      skip: 1
    });
    expect(plan.actions.map((action) => [action.code, action.action])).toEqual([
      ["new-code", "create"],
      ["existing-update", "update"],
      ["existing-same", "unchanged"],
      ["broken", "skip"]
    ]);
    expect(repository.upserted).toHaveLength(0);
  });

  it("applies only create and update actions when explicitly requested", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const redisReader = new FakeInvitationRedisReader();
    redisReader.invitations = [
      legacyInvite("new-code", { expiresAt: future }),
      legacyInvite("existing-update", { remaining: 1, expiresAt: future }),
      legacyInvite("existing-same", { expiresAt: future }),
      legacyInvite("broken", { remaining: null, expiresAt: future })
    ];
    const repository = new FakeInvitationIdentityRepository();
    repository.rows.set("existing-update", identityInvite("existing-update", { remaining: 2, expiresAt: future }));
    repository.rows.set("existing-same", identityInvite("existing-same", { expiresAt: future }));
    const importer = new InvitationImportService(
      redisReader as unknown as InvitationRedisReader,
      repository as unknown as InvitationIdentityRepository
    );

    const result = await importer.importFromLegacy({ apply: true });

    expect(result.applied).toBe(true);
    expect(result.affectedRows).toBe(2);
    expect(repository.upserted).toHaveLength(1);
    expect(repository.upserted[0].map((invitation) => invitation.code)).toEqual(["new-code", "existing-update"]);
  });

  it("refuses to plan an import when a source is not configured", async () => {
    const redisReader = new FakeInvitationRedisReader();
    redisReader.configured = false;
    const repository = new FakeInvitationIdentityRepository();
    const importer = new InvitationImportService(
      redisReader as unknown as InvitationRedisReader,
      repository as unknown as InvitationIdentityRepository
    );

    const plan = await importer.plan();

    expect(plan).toMatchObject({
      sourceConfigured: false,
      identityDbConfigured: true,
      summary: {
        create: 0,
        update: 0,
        unchanged: 0,
        skip: 1
      },
      actions: [
        {
          code: "*",
          action: "skip",
          reason: "legacy Redis is not configured"
        }
      ]
    });
  });
});

describe("identity-adapter native invitation management API", () => {
  let app: INestApplication | null = null;
  let redisReader: FakeInvitationRedisReader;
  let identityRepository: FakeInvitationIdentityRepository;
  let legacyRedisRepository: FakeInvitationLegacyRedisRepository;
  let recordRepository: FakeInvitationRecordRepository;
  let sessionRepository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "native";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_ACCOUNT_INVITATION_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_INVITATION_MANAGEMENT_NATIVE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_INVITATION_CHECK_NATIVE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED = "true";
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "invitation-management-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-invitation-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-invitation";

    redisReader = new FakeInvitationRedisReader();
    identityRepository = new FakeInvitationIdentityRepository();
    legacyRedisRepository = new FakeInvitationLegacyRedisRepository();
    recordRepository = new FakeInvitationRecordRepository();
    legacyRedisRepository.rows.set("abc123", {});
    sessionRepository = new FakeIdentitySessionRepository();
    app = await createNativeInvitationManagementTestApp(
      redisReader,
      identityRepository,
      legacyRedisRepository,
      recordRepository,
      sessionRepository
    );
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("reports invitation management readiness independently from public registration paths", async () => {
    const readiness = await request(app!.getHttpServer()).get("/internal/account-lifecycle/readiness").expect(200);

    expect(readiness.body.data).toMatchObject({
      nativeInvitationManagementConfigured: true,
      nativeInvitationCheckConfigured: true,
      nativeInvitationRecordsConfigured: true,
      scopes: {
        invitation: true,
        invitationManagementNative: true,
        invitationCheckNative: true,
        invitationRecordsNative: true
      }
    });
  });

  it("lists invitations in the old management response shape from legacy Redis", async () => {
    const login = await loginAs(app!, "guanfei");
    redisReader.invitations = [
      legacyInvite("older", { createdAt: 100, quota: 3, remaining: 0 }),
      legacyInvite("newer", { createdAt: 200, quota: 2, remaining: 1, note: "team" })
    ];

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/invitations")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toEqual([
      expect.objectContaining({
        code: "newer",
        quota: 2,
        remaining: 1,
        note: "team",
        status: "active"
      }),
      expect.objectContaining({
        code: "older",
        quota: 3,
        remaining: 0,
        status: "used_up"
      })
    ]);
  });

  it("creates invitations with identity DB and legacy Redis dual-write", async () => {
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .post("/v1/plugin-user/create-invitation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ quota: 3, expiresIn: 3600, note: "internal" })
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        quota: 3,
        remaining: 3,
        creatorId: 24,
        creatorName: "guanfei",
        note: "internal"
      }
    });
    expect(response.body.data.code).toMatch(/^[0-9a-f]{8}$/);
    expect(identityRepository.rows.get(response.body.data.code)).toMatchObject({
      inviteCode: response.body.data.code,
      quota: 3,
      remaining: 3,
      source: "identity-service-dual-write"
    });
    expect(legacyRedisRepository.created[0]).toMatchObject({
      code: response.body.data.code,
      quota: 3,
      remaining: 3,
      creatorId: 24,
      creatorName: "guanfei",
      note: "internal"
    });
  });

  it("deletes invitations with identity DB mark-delete and legacy Redis delete", async () => {
    const login = await loginAs(app!, "guanfei");
    identityRepository.rows.set("abc123", identityInvite("abc123"));

    const response = await request(app!.getHttpServer())
      .post("/v1/plugin-user/delete-invitation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ code: "abc123" })
      .expect(200);

    expect(response.body).toEqual({
      code: 0,
      message: "邀请已撤销"
    });
    expect(identityRepository.rows.get("abc123")?.status).toBe("deleted");
    expect(legacyRedisRepository.deleted).toEqual(["abc123"]);
  });

  it("keeps invitation management protected by elevated roles", async () => {
    const login = await loginAs(app!, "unverified");

    const response = await request(app!.getHttpServer())
      .post("/v1/plugin-user/create-invitation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ quota: 1 })
      .expect(403);

    expect(response.body).toEqual({
      code: 2003,
      message: "没有权限执行此操作"
    });
  });

  it("lists invitation records in the old response shape from legacy MySQL", async () => {
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/invitation-records?code=abc123")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toEqual([
      {
        id: 2,
        invite_code: "abc123",
        inviter_id: 24,
        invitee_id: 26,
        created_at: 1770365000,
        username: "newer-user",
        email: "newer@example.com"
      },
      {
        id: 1,
        invite_code: "abc123",
        inviter_id: 24,
        invitee_id: 25,
        created_at: 1770364900,
        username: "older-user",
        email: "older@example.com"
      }
    ]);
  });

  it("keeps invitation records protected by elevated roles", async () => {
    const login = await loginAs(app!, "unverified");

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/invitation-records?code=abc123")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(403);

    expect(response.body).toEqual({
      code: 2003,
      message: "没有权限执行此操作"
    });
  });

  it("falls back to legacy proxy when native invitation records are disabled", async () => {
    await app?.close();
    process.env.IDENTITY_ACCOUNT_INVITATION_RECORDS_NATIVE_ENABLED = "false";
    redisReader = new FakeInvitationRedisReader();
    identityRepository = new FakeInvitationIdentityRepository();
    legacyRedisRepository = new FakeInvitationLegacyRedisRepository();
    recordRepository = new FakeInvitationRecordRepository();
    sessionRepository = new FakeIdentitySessionRepository();
    app = await createNativeInvitationManagementTestApp(
      redisReader,
      identityRepository,
      legacyRedisRepository,
      recordRepository,
      sessionRepository
    );
    const login = await loginAs(app!, "guanfei");
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify([{ id: 99, invite_code: "legacy" }]), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/invitation-records?code=abc123")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toEqual([{ id: 99, invite_code: "legacy" }]);
    const [url] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/plugin-user/invitation-records?code=abc123");
  });

  it("keeps public invitation registration endpoints on legacy proxy", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ code: 0, message: "legacy register" }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app!.getHttpServer())
      .post("/v1/plugin-user/register")
      .send({
        inviteCode: "abc123",
        username: "new-user",
        password: "R3gister!234",
        email: "new@example.com",
        verificationCode: "123456"
      })
      .expect(201);

    expect(response.body).toEqual({ code: 0, message: "legacy register" });
    const [url] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/plugin-user/register");
  });

  it("checks invitations from identity DB without requiring authentication", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    identityRepository.rows.set("abc123", identityInvite("abc123", { remaining: 2, expiresAt: future }));
    redisReader.invitations = [legacyInvite("abc123", { remaining: 2, expiresAt: future })];

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/check-invitation?code=abc123")
      .expect(200);

    expect(response.body).toEqual({
      valid: true,
      remaining: 2,
      expiresAt: future
    });
  });

  it("returns old invalid invitation shapes for expired and used-up identity invitations", async () => {
    const past = Math.floor(Date.now() / 1000) - 60;
    const future = Math.floor(Date.now() / 1000) + 3600;
    identityRepository.rows.set("expired", identityInvite("expired", { remaining: 2, expiresAt: past, status: "expired" }));
    identityRepository.rows.set("used-up", identityInvite("used-up", { remaining: 0, expiresAt: future, status: "used_up" }));
    redisReader.configured = false;

    const expired = await request(app!.getHttpServer())
      .get("/v1/plugin-user/check-invitation?code=expired")
      .expect(200);
    const usedUp = await request(app!.getHttpServer())
      .get("/v1/plugin-user/check-invitation?code=used-up")
      .expect(200);

    expect(expired.body).toEqual({
      valid: false,
      reason: "邀请码已过期"
    });
    expect(usedUp.body).toEqual({
      valid: false,
      reason: "邀请名额已用完"
    });
  });

  it("falls back to legacy proxy when identity DB and legacy Redis check results differ", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    identityRepository.rows.set("abc123", identityInvite("abc123", { remaining: 2, expiresAt: future }));
    redisReader.invitations = [legacyInvite("abc123", { remaining: 1, expiresAt: future })];
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ valid: true, remaining: 1, expiresAt: future }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app!.getHttpServer())
      .get("/v1/plugin-user/check-invitation?code=abc123")
      .expect(200);

    expect(response.body).toEqual({
      valid: true,
      remaining: 1,
      expiresAt: future
    });
    const [url] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/plugin-user/check-invitation?code=abc123");
  });
});

describe("identity-adapter native register lifecycle API", () => {
  let app: INestApplication | null = null;
  let registrationRepository: FakeAccountRegistrationRepository;
  let operationRepository: FakeAccountLifecycleOperationRepository;
  let sessionRepository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "native";
    process.env.IDENTITY_ACCOUNT_REGISTER_ENABLED = "true";
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "register-native-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-register-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-register";

    registrationRepository = new FakeAccountRegistrationRepository();
    operationRepository = new FakeAccountLifecycleOperationRepository();
    sessionRepository = new FakeIdentitySessionRepository();
    app = await createNativeRegisterTestApp(registrationRepository, operationRepository, sessionRepository);
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("reports native register readiness separately from the lifecycle flag", async () => {
    registrationRepository.configured = false;

    const readiness = await request(app!.getHttpServer()).get("/internal/account-lifecycle/readiness").expect(200);
    expect(readiness.body.data).toMatchObject({
      enabled: true,
      mode: "native",
      nativeRegisterConfigured: false,
      scopes: {
        register: true
      }
    });

    await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "new-user@example.com", password: "R3gister!234" })
      .expect(503);
  });

  it("creates a native standard registration and returns a token compatible with phase 4", async () => {
    const response = await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "new-user@example.com", password: "R3gister!234" })
      .expect(201);

    expect(response.body).toMatchObject({
      success: true,
      message: "register",
      uid: 1000,
      token: {
        tokenType: "Bearer",
        refreshToken: "refresh-1"
      }
    });
    expect(response.body.token.token).toBe(response.body.token.accessToken);

    const payload = decodeJwtPayload(response.body.token.accessToken);
    expect(payload).toMatchObject({
      iss: "identity-register-test",
      aud: "xrugc-register",
      sub: "1000",
      uid: 1000,
      username: "new-user@example.com",
      roles: ["user"]
    });
  });

  it("keeps repeated native standard registration idempotent", async () => {
    const first = await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "retry-user@example.com", password: "R3gister!234" })
      .expect(201);

    const second = await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "retry-user@example.com", password: "R3gister!234" })
      .expect(201);

    expect(first.body.uid).toBe(1000);
    expect(second.body.uid).toBe(1000);
    expect(second.body.token.refreshToken).toBe("refresh-2");
    expect(registrationRepository.users.size).toBe(1);
  });

  it("creates a native wechat registration and binds the wechat token once", async () => {
    const response = await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "wechat-token", username: "wechat-user@example.com", password: "R3gister!234" })
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      message: "register",
      uid: 1000,
      token: {
        refreshToken: "refresh-1"
      }
    });
    expect(registrationRepository.wechatBindings.get("wechat-token")).toBe(1000);

    await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "wechat-token", username: "other-user@example.com", password: "R3gister!234" })
      .expect(400);
  });

  it("keeps repeated native wechat registration idempotent for the same request", async () => {
    const payload = { token: "wechat-token", username: "wechat-retry@example.com", password: "R3gister!234" };

    const first = await request(app!.getHttpServer()).post("/v1/wechat/register").send(payload).expect(200);
    const second = await request(app!.getHttpServer()).post("/v1/wechat/register").send(payload).expect(200);

    expect(first.body.uid).toBe(1000);
    expect(second.body.uid).toBe(1000);
    expect(second.body.token.refreshToken).toBe("refresh-2");
    expect(registrationRepository.users.size).toBe(1);
  });

  it("keeps legacy-compatible errors for wechat registration edge cases", async () => {
    const noWechat = await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "missing-token", username: "wechat-user@example.com", password: "R3gister!234" })
      .expect(400);
    expect(noWechat.text).toContain("no wechat");

    const registered = await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "registered-wechat-token", username: "wechat-user@example.com", password: "R3gister!234" })
      .expect(400);
    expect(registered.text).toContain("already registered,24");
  });

  it("returns password policy errors in the existing frontend-friendly shape", async () => {
    const response = await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "new-user@example.com", password: "123456" })
      .expect(400);

    expect(response.body.password).toEqual(
      expect.arrayContaining([
        "密码长度不能少于 8 个字符",
        "密码必须在大写字母、小写字母、数字、特殊字符中至少包含 3 类"
      ])
    );
  });
});

describe("identity-adapter native password lifecycle API", () => {
  let app: INestApplication | null = null;
  let operationRepository: FakeAccountLifecycleOperationRepository;
  let passwordRepository: FakeAccountPasswordRepository;
  let sessionRepository: FakeIdentitySessionRepository;
  let legacySessionRevocation: FakeLegacySessionRevocationService;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "native";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_ACCOUNT_PASSWORD_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_PASSWORD_CHANGE_NATIVE_ENABLED = "true";
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "password-native-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-password-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-password";

    operationRepository = new FakeAccountLifecycleOperationRepository();
    passwordRepository = new FakeAccountPasswordRepository();
    sessionRepository = new FakeIdentitySessionRepository();
    legacySessionRevocation = new FakeLegacySessionRevocationService();
    app = await createNativePasswordTestApp(operationRepository, passwordRepository, sessionRepository, legacySessionRevocation);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("changes password with an identity token and revokes identity refresh sessions", async () => {
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .post("/v1/password/change")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({
        old_password: "123456",
        new_password: "N3wSafe!234",
        confirm_password: "N3wSafe!234"
      })
      .expect(200);

    expect(response.body).toEqual({
      success: true,
      message: "密码修改成功，请重新登录"
    });
    expect(passwordRepository.users.get(24)?.changeCount).toBe(1);
    expect([...sessionRepository.sessions.values()].every((session) => session.revokedAt)).toBe(true);
    expect(legacySessionRevocation.calls).toEqual([{ legacyUserId: 24, reason: "password.change" }]);
  });

  it("keeps repeated password change idempotent after the old password has changed", async () => {
    const login = await loginAs(app!, "guanfei");
    const payload = {
      old_password: "123456",
      new_password: "N3wSafe!234",
      confirm_password: "N3wSafe!234"
    };

    await request(app!.getHttpServer()).post("/v1/password/change").set("Authorization", `Bearer ${login.accessToken}`).send(payload).expect(200);
    await request(app!.getHttpServer()).post("/v1/password/change").set("Authorization", `Bearer ${login.accessToken}`).send(payload).expect(200);

    expect(passwordRepository.users.get(24)?.changeCount).toBe(1);
    expect(legacySessionRevocation.calls).toHaveLength(1);
  });

  it("keeps password change successful when legacy session compensation fails", async () => {
    legacySessionRevocation.fail = true;
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .post("/v1/password/change")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({
        old_password: "123456",
        new_password: "N3wSafe!234",
        confirm_password: "N3wSafe!234"
      })
      .expect(200);

    expect(response.body).toEqual({
      success: true,
      message: "密码修改成功，请重新登录"
    });
    expect(legacySessionRevocation.calls).toEqual([{ legacyUserId: 24, reason: "password.change" }]);
  });

  it("rejects wrong old passwords without changing the legacy hash", async () => {
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .post("/v1/password/change")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({
        old_password: "wrong",
        new_password: "N3wSafe!234",
        confirm_password: "N3wSafe!234"
      })
      .expect(400);

    expect(response.body.error).toMatchObject({
      code: "INVALID_REQUEST",
      message: "旧密码不正确"
    });
    expect(passwordRepository.users.get(24)?.changeCount).toBe(0);
  });

  it("requires verified email before native password change", async () => {
    const login = await loginAs(app!, "unverified");

    const response = await request(app!.getHttpServer())
      .post("/v1/password/change")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({
        old_password: "123456",
        new_password: "N3wSafe!234",
        confirm_password: "N3wSafe!234"
      })
      .expect(400);

    expect(response.body.error).toMatchObject({
      code: "INVALID_REQUEST",
      message: "邮箱未验证，请先完成邮箱验证后再修改密码"
    });
  });

  it("keeps reset-code endpoints on legacy proxy while change password is native", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ success: true, message: "找回密码验证码已发送到您的邮箱" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app!.getHttpServer())
      .post("/v1/password/request-reset")
      .send({ email: "verified@example.com" })
      .expect(200);

    expect(response.body).toEqual({ success: true, message: "找回密码验证码已发送到您的邮箱" });
    const [url] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/password/request-reset");
  });
});

describe("identity-adapter native password reset lifecycle API", () => {
  let app: INestApplication | null = null;
  let operationRepository: FakeAccountLifecycleOperationRepository;
  let passwordRepository: FakeAccountPasswordRepository;
  let challengeRepository: FakePasswordResetChallengeRepository;
  let emailDelivery: FakeEmailDeliveryService;
  let sessionRepository: FakeIdentitySessionRepository;
  let legacySessionRevocation: FakeLegacySessionRevocationService;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "native";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_ACCOUNT_PASSWORD_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED = "true";
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "password-reset-native-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-password-reset-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-password-reset";
    process.env.IDENTITY_EMAIL_WEBHOOK_URL = "http://mail-webhook/send";

    operationRepository = new FakeAccountLifecycleOperationRepository();
    passwordRepository = new FakeAccountPasswordRepository();
    challengeRepository = new FakePasswordResetChallengeRepository();
    emailDelivery = new FakeEmailDeliveryService();
    sessionRepository = new FakeIdentitySessionRepository();
    legacySessionRevocation = new FakeLegacySessionRevocationService();
    app = await createNativePasswordResetTestApp(
      operationRepository,
      passwordRepository,
      challengeRepository,
      emailDelivery,
      sessionRepository,
      legacySessionRevocation
    );
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("reports reset native as not ready when email delivery is disabled", async () => {
    emailDelivery.configured = false;

    const readiness = await request(app!.getHttpServer()).get("/internal/account-lifecycle/readiness").expect(200);
    expect(readiness.body.data).toMatchObject({
      nativePasswordResetConfigured: false
    });

    await request(app!.getHttpServer())
      .post("/v1/password/request-reset")
      .send({ email: "ogre3d@163.com" })
      .expect(503);
  });

  it("sends a native password reset code through the email delivery service", async () => {
    const response = await request(app!.getHttpServer())
      .post("/v1/password/request-reset")
      .send({ email: "ogre3d@163.com", locale: "zh-CN" })
      .expect(200);

    expect(response.body).toEqual({
      success: true,
      message: "找回密码验证码已发送到您的邮箱"
    });
    expect(emailDelivery.sent).toEqual([{ email: "ogre3d@163.com", code: "123456", locale: "zh-CN" }]);
  });

  it("keeps request reset rate limits in native reset mode", async () => {
    challengeRepository.rateLimited = true;

    const response = await request(app!.getHttpServer())
      .post("/v1/password/request-reset")
      .send({ email: "ogre3d@163.com" })
      .expect(429);

    expect(response.body.error).toMatchObject({
      code: "RATE_LIMIT_EXCEEDED",
      retry_after: 60
    });
  });

  it("verifies native reset codes and reports invalid codes", async () => {
    await request(app!.getHttpServer()).post("/v1/password/request-reset").send({ email: "ogre3d@163.com" }).expect(200);

    const invalid = await request(app!.getHttpServer())
      .post("/v1/password/verify-code")
      .send({ email: "ogre3d@163.com", code: "000000" })
      .expect(400);
    expect(invalid.body.error).toMatchObject({
      code: "INVALID_CODE",
      message: "验证码不正确"
    });

    const valid = await request(app!.getHttpServer())
      .post("/v1/password/verify-code")
      .send({ email: "ogre3d@163.com", code: "123456" })
      .expect(200);
    expect(valid.body).toEqual({
      success: true,
      valid: true,
      message: "验证码有效"
    });
  });

  it("resets the legacy password and keeps repeated reset requests idempotent", async () => {
    await loginAs(app!, "guanfei");
    await request(app!.getHttpServer()).post("/v1/password/request-reset").send({ email: "ogre3d@163.com" }).expect(200);
    const payload = { email: "ogre3d@163.com", code: "123456", password: "R3setSafe!234" };

    const first = await request(app!.getHttpServer()).post("/v1/password/reset").send(payload).expect(200);
    const second = await request(app!.getHttpServer()).post("/v1/password/reset").send(payload).expect(200);

    expect(first.body).toEqual({
      success: true,
      message: "密码重置成功，请使用新密码登录"
    });
    expect(second.body).toEqual(first.body);
    expect(passwordRepository.users.get(24)?.changeCount).toBe(1);
    expect(challengeRepository.challenges.get("ogre3d@163.com")?.consumedAt).toBeInstanceOf(Date);
    expect([...sessionRepository.sessions.values()].every((session) => session.revokedAt)).toBe(true);
    expect(legacySessionRevocation.calls).toEqual([{ legacyUserId: 24, reason: "password.reset" }]);
  });

  it("keeps password reset successful when legacy session compensation fails", async () => {
    legacySessionRevocation.fail = true;
    await loginAs(app!, "guanfei");
    await request(app!.getHttpServer()).post("/v1/password/request-reset").send({ email: "ogre3d@163.com" }).expect(200);

    const response = await request(app!.getHttpServer())
      .post("/v1/password/reset")
      .send({ email: "ogre3d@163.com", code: "123456", password: "R3setSafe!234" })
      .expect(200);

    expect(response.body).toEqual({
      success: true,
      message: "密码重置成功，请使用新密码登录"
    });
    expect(legacySessionRevocation.calls).toEqual([{ legacyUserId: 24, reason: "password.reset" }]);
  });
});

describe("identity-adapter native email lifecycle API", () => {
  let app: INestApplication | null = null;
  let emailRepository: FakeAccountEmailRepository;
  let challengeRepository: FakeEmailVerificationChallengeRepository;
  let changeTokenRepository: FakeEmailChangeTokenRepository;
  let emailDelivery: FakeEmailDeliveryService;
  let sessionRepository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_MODE = "native";
    process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_ACCOUNT_EMAIL_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED = "true";
    process.env.IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED = "true";
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "email-native-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-email-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-email";
    process.env.IDENTITY_EMAIL_WEBHOOK_URL = "http://mail-webhook/send";

    emailRepository = new FakeAccountEmailRepository();
    challengeRepository = new FakeEmailVerificationChallengeRepository();
    changeTokenRepository = new FakeEmailChangeTokenRepository();
    emailDelivery = new FakeEmailDeliveryService();
    sessionRepository = new FakeIdentitySessionRepository();
    app = await createNativeEmailTestApp(emailRepository, challengeRepository, changeTokenRepository, emailDelivery, sessionRepository);
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("reports email native as not ready when email delivery is disabled", async () => {
    emailDelivery.configured = false;
    const login = await loginAs(app!, "unverified");

    const readiness = await request(app!.getHttpServer()).get("/internal/account-lifecycle/readiness").expect(200);
    expect(readiness.body.data).toMatchObject({
      nativeEmailVerifyConfigured: false,
      nativeEmailChangeConfigured: false,
      scopes: {
        email: true,
        emailVerifyNative: true,
        emailChangeNative: true
      }
    });

    await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "new@example.com" })
      .expect(503);
  });

  it("returns native email status in the old frontend shape", async () => {
    const login = await loginAs(app!, "guanfei");

    const response = await request(app!.getHttpServer())
      .get("/v1/email/status")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      data: {
        user_id: 24,
        username: "guanfei",
        email: "ogre3d@163.com",
        email_verified: true,
        email_verified_at: 1772210253
      }
    });
    expect(response.body.data.email_verified_at_formatted).toEqual(expect.any(String));
  });

  it("sends native email verification codes and reports cooldown", async () => {
    const login = await loginAs(app!, "unverified");

    const sent = await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "New@Example.com", locale: "zh-CN" })
      .expect(200);

    expect(sent.body).toEqual({
      success: true,
      message: "验证码已发送到您的邮箱"
    });
    expect(emailDelivery.sent).toEqual([{ email: "new@example.com", code: "654321", locale: "zh-CN" }]);

    const cooldown = await request(app!.getHttpServer())
      .get("/v1/email/cooldown?email=new@example.com")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(cooldown.body.data).toMatchObject({
      email: "new@example.com",
      can_send: false,
      limit_seconds: 60
    });
    expect(cooldown.body.data.retry_after).toBeGreaterThan(0);
  });

  it("verifies native email codes and binds the legacy user email", async () => {
    const login = await loginAs(app!, "unverified");
    await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "bind@example.com" })
      .expect(200);

    const invalid = await request(app!.getHttpServer())
      .post("/v1/email/verify")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "bind@example.com", code: "000000" })
      .expect(400);
    expect(invalid.body.error).toMatchObject({
      code: "INVALID_CODE",
      message: "验证码不正确"
    });

    const response = await request(app!.getHttpServer())
      .post("/v1/email/verify")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "bind@example.com", code: "654321" })
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      message: "邮箱验证并绑定成功",
      data: {
        user: {
          id: 25,
          username: "unverified",
          email: "bind@example.com"
        }
      }
    });
    expect(response.body.data.user.email_verified_at).toEqual(expect.any(Number));
    expect(emailRepository.users.get(25)?.email).toBe("bind@example.com");
    expect(challengeRepository.challenges.get("bind@example.com")?.consumedAt).toBeInstanceOf(Date);
  });

  it("keeps native email rate limits and account locks", async () => {
    const login = await loginAs(app!, "unverified");
    challengeRepository.rateLimited = true;

    const limited = await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "limited@example.com" })
      .expect(429);
    expect(limited.body.error).toMatchObject({
      code: "RATE_LIMIT_EXCEEDED",
      retry_after: 60
    });

    challengeRepository.rateLimited = false;
    await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "locked@example.com" })
      .expect(200);

    for (let i = 0; i < 5; i += 1) {
      await request(app!.getHttpServer())
        .post("/v1/email/verify")
        .set("Authorization", `Bearer ${login.accessToken}`)
        .send({ email: "locked@example.com", code: "000000" })
        .expect(400);
    }

    const locked = await request(app!.getHttpServer())
      .post("/v1/email/verify")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "locked@example.com", code: "654321" })
      .expect(429);
    expect(locked.body.error).toMatchObject({
      code: "ACCOUNT_LOCKED",
      retry_after: 900
    });
  });

  it("rejects email addresses already bound by another legacy user", async () => {
    const login = await loginAs(app!, "unverified");

    const response = await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "ogre3d@163.com" })
      .expect(400);

    expect(response.body.error).toMatchObject({
      code: "INVALID_CODE",
      message: "该邮箱已被其他账号绑定"
    });
    expect(emailDelivery.sent).toHaveLength(0);
  });

  it("sends current-email confirmation codes and issues native change tokens", async () => {
    const login = await loginAs(app!, "guanfei");

    const sent = await request(app!.getHttpServer())
      .post("/v1/email/send-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({})
      .expect(200);
    expect(sent.body).toEqual({
      success: true,
      message: "二次确认验证码已发送到当前绑定邮箱"
    });
    expect(emailDelivery.sent).toEqual([{ email: "ogre3d@163.com", code: "654321", locale: undefined }]);

    const token = await request(app!.getHttpServer())
      .post("/v1/email/verify-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ code: "654321" })
      .expect(200);
    expect(token.body).toEqual({
      success: true,
      message: "旧邮箱验证成功，请在 10 分钟内完成新邮箱绑定",
      data: {
        change_token: "change-token-123",
        expires_in: 600
      }
    });
    expect(challengeRepository.challenges.get("ogre3d@163.com")?.consumedAt).toBeInstanceOf(Date);
  });

  it("keeps native current-email confirmation rate limits", async () => {
    const login = await loginAs(app!, "guanfei");
    challengeRepository.rateLimited = true;

    const response = await request(app!.getHttpServer())
      .post("/v1/email/send-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({})
      .expect(429);

    expect(response.body.error).toMatchObject({
      code: "RATE_LIMIT_EXCEEDED",
      retry_after: 60
    });
    expect(emailDelivery.sent).toHaveLength(0);
  });

  it("changes a verified email only after old-email confirmation and new-email verification", async () => {
    const login = await loginAs(app!, "guanfei");
    await request(app!.getHttpServer())
      .post("/v1/email/send-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({})
      .expect(200);
    const token = await request(app!.getHttpServer())
      .post("/v1/email/verify-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ code: "654321" })
      .expect(200);

    await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "changed@example.com" })
      .expect(200);

    const changed = await request(app!.getHttpServer())
      .post("/v1/email/verify")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "changed@example.com", code: "654321", change_token: token.body.data.change_token })
      .expect(200);

    expect(changed.body).toMatchObject({
      success: true,
      message: "邮箱验证并绑定成功",
      data: {
        user: {
          id: 24,
          username: "guanfei",
          email: "changed@example.com"
        }
      }
    });
    expect(emailRepository.users.get(24)?.email).toBe("changed@example.com");
    expect(challengeRepository.challenges.get("changed@example.com")?.consumedAt).toBeInstanceOf(Date);
    expect(changeTokenRepository.tokens.get(24)?.consumedAt).toBeInstanceOf(Date);
  });

  it("rejects verified-email change when the native change token is missing or invalid", async () => {
    const login = await loginAs(app!, "guanfei");

    await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "changed@example.com" })
      .expect(200);

    const response = await request(app!.getHttpServer())
      .post("/v1/email/verify")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "changed@example.com", code: "654321", change_token: "bad-token" })
      .expect(400);

    expect(response.body.error).toMatchObject({
      code: "INVALID_CODE",
      message: "改绑确认已失效，请重新验证旧邮箱"
    });
    expect(emailRepository.users.get(24)?.email).toBe("ogre3d@163.com");
    expect(challengeRepository.challenges.get("changed@example.com")?.consumedAt).toBeNull();
  });

  it("unbinds a verified email with a current-email verification code", async () => {
    const login = await loginAs(app!, "guanfei");
    await request(app!.getHttpServer())
      .post("/v1/email/send-change-confirmation")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({})
      .expect(200);

    const response = await request(app!.getHttpServer())
      .post("/v1/email/unbind")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ code: "654321" })
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      message: "邮箱解绑成功",
      data: {
        user: {
          id: 24,
          username: "guanfei",
          email: null,
          email_verified_at: null
        }
      }
    });
    expect(emailRepository.users.get(24)?.email).toBeNull();
    expect(challengeRepository.challenges.get("ogre3d@163.com")?.consumedAt).toBeInstanceOf(Date);
  });

  it("unbinds an unverified email without a verification code", async () => {
    const login = await loginAs(app!, "unverified");

    const response = await request(app!.getHttpServer())
      .post("/v1/email/unbind")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({})
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      message: "邮箱解绑成功",
      data: {
        user: {
          id: 25,
          username: "unverified",
          email: null,
          email_verified_at: null
        }
      }
    });
    expect(emailRepository.users.get(25)?.email).toBeNull();
  });

  it("falls back to legacy proxy for verified-email change flows", async () => {
    await app?.close();
    process.env.IDENTITY_ACCOUNT_EMAIL_CHANGE_NATIVE_ENABLED = "false";
    emailRepository = new FakeAccountEmailRepository();
    challengeRepository = new FakeEmailVerificationChallengeRepository();
    changeTokenRepository = new FakeEmailChangeTokenRepository();
    emailDelivery = new FakeEmailDeliveryService();
    sessionRepository = new FakeIdentitySessionRepository();
    app = await createNativeEmailTestApp(emailRepository, challengeRepository, changeTokenRepository, emailDelivery, sessionRepository);

    const login = await loginAs(app!, "guanfei");
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ success: true, message: "legacy email flow" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app!.getHttpServer())
      .post("/v1/email/send-verification")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .send({ email: "changed@example.com" })
      .expect(200);

    expect(response.body).toEqual({ success: true, message: "legacy email flow" });
    const [url] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/email/send-verification");
  });
});

async function createLifecycleTestApp(): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .compile();

  const lifecycleApp = moduleRef.createNestApplication();
  await lifecycleApp.init();

  return lifecycleApp;
}

async function createInvitationDiagnosticsTestApp(
  redisReader: FakeInvitationRedisReader,
  recordRepository: FakeInvitationRecordRepository
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(InvitationRedisReader)
    .useValue(redisReader)
    .overrideProvider(InvitationRecordRepository)
    .useValue(recordRepository)
    .compile();

  const diagnosticsApp = moduleRef.createNestApplication();
  await diagnosticsApp.init();

  return diagnosticsApp;
}

async function createNativeRegisterTestApp(
  registrationRepository: FakeAccountRegistrationRepository,
  operationRepository: FakeAccountLifecycleOperationRepository,
  sessionRepository: FakeIdentitySessionRepository
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(AccountRegistrationRepository)
    .useValue(registrationRepository)
    .overrideProvider(AccountLifecycleOperationRepository)
    .useValue(operationRepository)
    .overrideProvider(IdentitySessionRepository)
    .useValue(sessionRepository)
    .compile();

  const nativeRegisterApp = moduleRef.createNestApplication();
  await nativeRegisterApp.init();

  return nativeRegisterApp;
}

async function createNativePasswordTestApp(
  operationRepository: FakeAccountLifecycleOperationRepository,
  passwordRepository: FakeAccountPasswordRepository,
  sessionRepository: FakeIdentitySessionRepository,
  legacySessionRevocation: FakeLegacySessionRevocationService
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(AccountLifecycleOperationRepository)
    .useValue(operationRepository)
    .overrideProvider(AccountPasswordRepository)
    .useValue(passwordRepository)
    .overrideProvider(IdentitySessionRepository)
    .useValue(sessionRepository)
    .overrideProvider(LegacySessionRevocationService)
    .useValue(legacySessionRevocation)
    .compile();

  const nativePasswordApp = moduleRef.createNestApplication();
  await nativePasswordApp.init();

  return nativePasswordApp;
}

async function createNativePasswordResetTestApp(
  operationRepository: FakeAccountLifecycleOperationRepository,
  passwordRepository: FakeAccountPasswordRepository,
  challengeRepository: FakePasswordResetChallengeRepository,
  emailDelivery: FakeEmailDeliveryService,
  sessionRepository: FakeIdentitySessionRepository,
  legacySessionRevocation: FakeLegacySessionRevocationService
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(AccountLifecycleOperationRepository)
    .useValue(operationRepository)
    .overrideProvider(AccountPasswordRepository)
    .useValue(passwordRepository)
    .overrideProvider(PasswordResetChallengeRepository)
    .useValue(challengeRepository)
    .overrideProvider(EmailDeliveryService)
    .useValue(emailDelivery)
    .overrideProvider(IdentitySessionRepository)
    .useValue(sessionRepository)
    .overrideProvider(LegacySessionRevocationService)
    .useValue(legacySessionRevocation)
    .compile();

  const nativePasswordResetApp = moduleRef.createNestApplication();
  await nativePasswordResetApp.init();

  return nativePasswordResetApp;
}

async function createNativeEmailTestApp(
  emailRepository: FakeAccountEmailRepository,
  challengeRepository: FakeEmailVerificationChallengeRepository,
  changeTokenRepository: FakeEmailChangeTokenRepository,
  emailDelivery: FakeEmailDeliveryService,
  sessionRepository: FakeIdentitySessionRepository
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(AccountEmailRepository)
    .useValue(emailRepository)
    .overrideProvider(EmailVerificationChallengeRepository)
    .useValue(challengeRepository)
    .overrideProvider(EmailChangeTokenRepository)
    .useValue(changeTokenRepository)
    .overrideProvider(EmailDeliveryService)
    .useValue(emailDelivery)
    .overrideProvider(IdentitySessionRepository)
    .useValue(sessionRepository)
    .compile();

  const nativeEmailApp = moduleRef.createNestApplication();
  await nativeEmailApp.init();

  return nativeEmailApp;
}

async function createNativeInvitationManagementTestApp(
  redisReader: FakeInvitationRedisReader,
  identityRepository: FakeInvitationIdentityRepository,
  legacyRedisRepository: FakeInvitationLegacyRedisRepository,
  recordRepository: FakeInvitationRecordRepository,
  sessionRepository: FakeIdentitySessionRepository
): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(InvitationRedisReader)
    .useValue(redisReader)
    .overrideProvider(InvitationIdentityRepository)
    .useValue(identityRepository)
    .overrideProvider(InvitationLegacyRedisRepository)
    .useValue(legacyRedisRepository)
    .overrideProvider(InvitationRecordRepository)
    .useValue(recordRepository)
    .overrideProvider(AccountInvitationService)
    .useValue(
      new AccountInvitationService(
        identityRepository as unknown as InvitationIdentityRepository,
        legacyRedisRepository as unknown as InvitationLegacyRedisRepository,
        redisReader as unknown as InvitationRedisReader,
        recordRepository as unknown as InvitationRecordRepository,
        new JwtIssuerService()
      )
    )
    .overrideProvider(IdentitySessionRepository)
    .useValue(sessionRepository)
    .compile();

  const nativeInvitationApp = moduleRef.createNestApplication();
  await nativeInvitationApp.init();

  return nativeInvitationApp;
}

async function loginAs(app: INestApplication, username: string) {
  const response = await request(app.getHttpServer())
    .post("/v1/auth/login")
    .send({ username, password: "123456" })
    .expect(201);

  return {
    accessToken: response.body.token.accessToken as string,
    refreshToken: response.body.token.refreshToken as string
  };
}

describe("identity-adapter token issuance API", () => {
  let app: INestApplication;
  let repository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-api";
    process.env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS = "3600";
    process.env.IDENTITY_REFRESH_TOKEN_TTL_SECONDS = "604800";

    repository = new FakeIdentitySessionRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(IdentitySessionRepository)
      .useValue(repository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app.close();
  });

  it("logs in with legacy credentials and returns a backward-compatible token shape", async () => {
    const response = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    expect(response.body).toMatchObject({
      success: true,
      message: "login",
      token: {
        tokenType: "Bearer",
        refreshToken: "refresh-1"
      }
    });
    expect(response.body.token.token).toBe(response.body.token.accessToken);

    const payload = decodeJwtPayload(response.body.token.accessToken);
    expect(payload).toMatchObject({
      iss: "identity-test",
      aud: "xrugc-api",
      sub: "24",
      uid: 24,
      username: "guanfei",
      roles: ["admin"]
    });
    expect(payload.session_id).toEqual(expect.any(String));
    expect(payload.jti).toEqual(expect.any(String));

    const jwks = await request(app.getHttpServer()).get("/jwks.json").expect(200);
    expect(jwks.body.keys[0]).toMatchObject({
      kid: "test-key",
      alg: "ES256",
      use: "sig"
    });
  });

  it("rejects wrong passwords without issuing a refresh session", async () => {
    await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "wrong" })
      .expect(401);

    expect(repository.sessions.size).toBe(0);
  });

  it("rotates refresh tokens and rejects replay of the old token", async () => {
    const login = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    const refresh = await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    expect(refresh.body.message).toBe("refresh");
    expect(refresh.body.token.refreshToken).toBe("refresh-2");

    await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(401);
  });

  it("keeps logout idempotent and revokes the refresh token", async () => {
    const login = await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "123456" })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/logout")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/logout")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(201);

    await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: login.body.token.refreshToken })
      .expect(401);
  });
});

describe("identity-adapter login audit API", () => {
  let app: INestApplication;
  let repository: FakeLoginAuditRepository;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    process.env.IDENTITY_LOGIN_AUDIT_ENABLED = "true";
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";
    process.env.IDENTITY_LOGIN_AUDIT_HASH_SALT = "test-salt";
    process.env.IDENTITY_DB_HOST = "identity-mysql";
    process.env.IDENTITY_DB_USER = "identity";

    repository = new FakeLoginAuditRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(LoginAuditRepository)
      .useValue(repository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app.close();
  });

  it("requires the internal service token", async () => {
    await request(app.getHttpServer())
      .post("/internal/login-events")
      .send({
        eventKey: "legacy-login:24:missing-token",
        legacyUserId: 24,
        username: "guanfei"
      })
      .expect(401);
  });

  it("records successful login events without leaking raw client data", async () => {
    const payload = {
      eventKey: "legacy-login:24:session-1",
      legacyUserId: 24,
      username: "guanfei",
      eventType: "login",
      success: true,
      occurredAt: "2026-06-06T14:30:00.000Z",
      ipAddress: "127.0.0.1",
      userAgent: "Mozilla/5.0",
      source: "legacy-backend",
      traceId: "session-1",
      metadata: {
        provider: "password",
        token: "should-not-persist",
        nested: { password: "secret", safe: "ok" }
      }
    };

    const first = await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    expect(first.body).toEqual({ accepted: true, duplicate: false });

    const event = repository.events.get(payload.eventKey);
    expect(event).toMatchObject({
      legacyUserId: 24,
      username: "guanfei",
      success: true,
      source: "legacy-backend"
    });
    expect(event?.ipAddressHash).toHaveLength(64);
    expect(event?.userAgentHash).toHaveLength(64);
    expect(event?.metadata).toEqual({
      provider: "password",
      token: "[filtered]",
      nested: { password: "[filtered]", safe: "ok" }
    });
  });

  it("keeps duplicate login events idempotent", async () => {
    const payload = {
      eventKey: "legacy-login:24:session-duplicate",
      legacyUserId: 24,
      username: "guanfei",
      occurredAt: "2026-06-06T14:30:00.000Z"
    };

    await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    const duplicate = await request(app.getHttpServer())
      .post("/internal/login-events")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send(payload)
      .expect(202);

    expect(duplicate.body).toEqual({ accepted: true, duplicate: true });

    const audit = await request(app.getHttpServer())
      .get("/internal/login-audit/users/24")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(audit.body.data.stats).toMatchObject({
      legacyUserId: 24,
      loginCount: 1,
      failedLoginCount: 0
    });
    expect(audit.body.data.recentEvents).toHaveLength(1);
  });

  it("filters sensitive metadata recursively", () => {
    expect(
      sanitizeMetadata({
        token: "abc",
        nested: {
          authorization: "Bearer abc",
          safe: "value"
        }
      })
    ).toEqual({
      token: "[filtered]",
      nested: {
        authorization: "[filtered]",
        safe: "value"
      }
    });
  });
});

function legacyInvite(code: string, overrides: Partial<LegacyRedisInvitation> = {}): LegacyRedisInvitation {
  const now = Math.floor(Date.now() / 1000);
  return {
    code,
    key: `invite:${code}`,
    quota: 2,
    remaining: 2,
    expiresAt: now + 3600,
    creatorId: 24,
    creatorName: "guanfei",
    note: "dev",
    createdAt: now,
    ttl: 3600,
    raw: {
      quota: "2",
      remaining: "2",
      expiresAt: String(now + 3600),
      creatorId: "24",
      creatorName: "guanfei",
      note: "dev",
      createdAt: String(now)
    },
    ...overrides
  };
}

function identityInvite(code: string, overrides: Partial<IdentityInvitation> = {}): IdentityInvitation {
  const now = Math.floor(Date.now() / 1000);
  return {
    inviteCode: code,
    quota: 2,
    remaining: 2,
    expiresAt: now + 3600,
    creatorLegacyUserId: 24,
    creatorName: "guanfei",
    note: "dev",
    legacyCreatedAt: now,
    status: "active",
    source: "legacy-redis",
    importedAt: null,
    lastSeenAt: null,
    ...overrides
  };
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const payload = token.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}
