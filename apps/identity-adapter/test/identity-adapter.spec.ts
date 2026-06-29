import "reflect-metadata";
import { createHash, generateKeyPairSync } from "node:crypto";
import { INestApplication, Logger } from "@nestjs/common";
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
import { IamRepository } from "../src/iam.repository.js";
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
import {
  InvalidAuthorizationCodeError,
  OidcAuthorizationCodeRepository
} from "../src/oidc-authorization-code.repository.js";
import { PasswordResetChallengeError, PasswordResetChallengeRepository } from "../src/password-reset-challenge.repository.js";
import {
  PluginUserWriteOperationInput,
  PluginUserWriteOperationRepository,
  pluginUserWriteOperationKey,
  pluginUserWriteRequestFingerprint,
  redactPluginUserWriteMetadata
} from "../src/plugin-user-write-operation.repository.js";
import { sanitizeMetadata } from "../src/login-audit.service.js";
import { assertReadonlySql } from "../src/readonly-write.guard.js";
import { normalizeOtlpTraceEndpoint, startTelemetry } from "../src/telemetry.js";
import {
  LoginAuditSourceEvent,
  UsageBillingRepository,
  UsageLedgerRecord,
  UsageReplayRunRow
} from "../src/usage-billing.repository.js";

class FakeLegacyIdentityReader {
  readonly passwordHash = bcrypt.hashSync("123456", 4);

  isConfigured() {
    return true;
  }

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

  async listUsers(input: { afterId: number; limit: number }) {
    const users = [await this.getUserById(24), await this.getUserById(25)].filter((user) => user !== null);
    return users.filter((user) => user!.id > input.afterId).slice(0, input.limit);
  }

  async listManagedUsers(input: {
    page: number;
    pageSize: number;
    search?: string;
    status?: number;
    sort?: string;
    order?: "asc" | "desc";
  }) {
    const all: any[] = [await this.getUserById(24), await this.getUserById(25)].filter((user) => user !== null);
    const search = input.search?.toLowerCase();
    let users = all.filter((user) => {
      if (search && !`${user.username ?? ""} ${user.email ?? ""}`.toLowerCase().includes(search)) {
        return false;
      }
      if (input.status !== undefined && user.status !== input.status) {
        return false;
      }
      return true;
    });

    const direction = input.order === "asc" ? 1 : -1;
    const sort = input.sort && ["id", "username", "nickname", "email", "created_at"].includes(input.sort) ? input.sort : "id";
    users = users.sort((a, b) => {
      const left = sort === "created_at" ? a.createdAt : a[sort];
      const right = sort === "created_at" ? b.createdAt : b[sort];
      return String(left ?? "").localeCompare(String(right ?? ""), undefined, { numeric: true }) * direction;
    });

    const page = Math.max(1, input.page);
    const pageSize = Math.max(1, input.pageSize);
    const total = users.length;
    return {
      users: users.slice((page - 1) * pageSize, page * pageSize),
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize)
    };
  }

  async listRoles() {
    return [{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }];
  }

  async listOrganizations() {
    return [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }];
  }

  async listUserPermissions(userId: number) {
    if (userId !== 24) {
      return [];
    }

    return [
      { name: "course.manage", description: "Manage courses", source: "role-child" as const },
      { name: "plugin.open", description: "Open plugins", source: "direct" as const }
    ];
  }
}

class FakePluginUserWriteOperationRepository {
  readonly inputs: PluginUserWriteOperationInput[] = [];

  isConfigured() {
    return true;
  }

  async begin(input: PluginUserWriteOperationInput) {
    this.inputs.push(input);
    return { duplicate: false };
  }
}

class FakeIamRepository {
  schemaEnsureCount = 0;
  schemaTablesReady = true;
  readonly identityUsers = new Map<number, any>([
    [
      24,
      {
        id: "id-user-24",
        legacyUserId: 24,
        keycloakSubject: "keycloak-subject-24",
        username: "guanfei",
        email: "ogre3d@163.com",
        status: "active",
        source: "legacy-shadow",
        metadata: {
          legacyNickname: "babamama",
          legacyEmailVerifiedAt: 1772210253,
          legacyCreatedAt: 1558664856,
          legacyUpdatedAt: 1763711034,
          legacyUserInfo: { locale: "zh-CN" }
        },
        createdAt: "2026-06-10T00:00:00.000Z",
        updatedAt: "2026-06-10T00:00:00.000Z"
      }
    ]
  ]);
  readonly subjectMaps = new Map<string, any[]>([
    [
      "id-user-24",
      [
        {
          identityUserId: "id-user-24",
          subjectType: "legacy_user",
          subjectId: "24",
          source: "legacy-shadow",
          status: "active",
          metadata: null,
          createdAt: null,
          updatedAt: null
        }
      ]
    ]
  ]);
  readonly roleAssignments = new Map<number, any[]>([
    [
      24,
      [
        {
          identityUserId: "id-user-24",
          legacyUserId: 24,
          roleName: "admin",
          source: "legacy-shadow",
          status: "shadow",
          observedAt: "2026-06-10T00:00:00.000Z"
        }
      ]
    ]
  ]);
  readonly organizationMemberships = new Map<number, any[]>([
    [
      24,
      [
        {
          identityUserId: "id-user-24",
          legacyUserId: 24,
          organizationId: 1,
          organizationRole: "member",
          source: "legacy-shadow",
          status: "shadow",
          metadata: {
            legacyName: "test-university",
            legacyTitle: "测试大学",
            legacyCreatedAt: 1,
            legacyUpdatedAt: 1
          },
          observedAt: "2026-06-10T00:00:00.000Z"
        }
      ]
    ]
  ]);
  readonly runs = new Map<string, any>();
  readonly items = new Map<string, any[]>();

  isConfigured() {
    return true;
  }

  async health() {
    return "configured";
  }

  async diagnostics() {
    return {
      identityDatabaseConfigured: true,
      tables: {
        identity_users: this.schemaTablesReady,
        identity_subject_maps: this.schemaTablesReady,
        identity_role_assignments_shadow: this.schemaTablesReady,
        identity_organization_memberships_shadow: this.schemaTablesReady,
        iam_reconciliation_runs: this.schemaTablesReady,
        iam_reconciliation_items: this.schemaTablesReady
      }
    };
  }

  async ensureSchema() {
    this.schemaEnsureCount += 1;
    this.schemaTablesReady = true;
  }

  async getIdentityUserByLegacyId(legacyUserId: number) {
    return this.identityUsers.get(legacyUserId) ?? null;
  }

  async listManagedUsers(input: {
    page: number;
    pageSize: number;
    search?: string;
    status?: number;
    sort?: string;
    order?: "asc" | "desc";
  }) {
    const search = input.search?.toLowerCase();
    let users = [...this.identityUsers.values()].filter((user) => {
      if (search && !`${user.username ?? ""} ${user.email ?? ""}`.toLowerCase().includes(search)) {
        return false;
      }
      if (input.status !== undefined && (input.status === 10 ? "active" : "inactive") !== user.status) {
        return false;
      }
      return user.legacyUserId !== null;
    });

    const direction = input.order === "asc" ? 1 : -1;
    const sort = input.sort && ["id", "username", "nickname", "email", "created_at"].includes(input.sort) ? input.sort : "id";
    users = users.sort((a, b) => {
      const left = sort === "id" ? a.legacyUserId : sort === "created_at" ? a.createdAt : a[sort];
      const right = sort === "id" ? b.legacyUserId : sort === "created_at" ? b.createdAt : b[sort];
      return String(left ?? "").localeCompare(String(right ?? ""), undefined, { numeric: true }) * direction;
    });

    const page = Math.max(1, input.page);
    const pageSize = Math.max(1, input.pageSize);
    const total = users.length;
    return {
      users: users.slice((page - 1) * pageSize, page * pageSize),
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize)
    };
  }

  async listSubjectMaps(identityUserId: string) {
    return this.subjectMaps.get(identityUserId) ?? [];
  }

  async listRoleAssignmentsShadow(legacyUserId: number) {
    return this.roleAssignments.get(legacyUserId) ?? [];
  }

  async listOrganizationMembershipsShadow(legacyUserId: number) {
    return this.organizationMemberships.get(legacyUserId) ?? [];
  }

  async upsertIdentityUserShadow(input: {
    identityUserId: string;
    legacyUserId: number;
    username: string | null;
    email: string | null;
    status: string;
    metadata: Record<string, unknown>;
  }) {
    this.identityUsers.set(input.legacyUserId, {
      id: input.identityUserId,
      legacyUserId: input.legacyUserId,
      keycloakSubject: null,
      username: input.username,
      email: input.email,
      status: input.status,
      source: "legacy-shadow",
      metadata: input.metadata,
      createdAt: "2026-06-10T00:00:00.000Z",
      updatedAt: "2026-06-10T00:00:00.000Z"
    });
    const current = this.subjectMaps.get(input.identityUserId) ?? [];
    const withoutLegacy = current.filter((subject) => !(subject.subjectType === "legacy_user" && subject.subjectId === String(input.legacyUserId)));
    this.subjectMaps.set(input.identityUserId, [
      ...withoutLegacy,
      {
        identityUserId: input.identityUserId,
        subjectType: "legacy_user",
        subjectId: String(input.legacyUserId),
        source: "legacy-shadow",
        status: "active",
        metadata: { legacyUserId: input.legacyUserId },
        createdAt: null,
        updatedAt: null
      }
    ]);
  }

  async upsertPluginSubjectMap(input: { identityUserId: string; legacyUserId: number; metadata: Record<string, unknown> }) {
    const current = this.subjectMaps.get(input.identityUserId) ?? [];
    const withoutPlugin = current.filter(
      (subject) => !(subject.subjectType === "plugin_user" && subject.subjectId === `legacy:${input.legacyUserId}`)
    );
    this.subjectMaps.set(input.identityUserId, [
      ...withoutPlugin,
      {
        identityUserId: input.identityUserId,
        subjectType: "plugin_user",
        subjectId: `legacy:${input.legacyUserId}`,
        source: "legacy-shadow",
        status: "active",
        metadata: input.metadata,
        createdAt: null,
        updatedAt: null
      }
    ]);
  }

  async replaceRoleAssignmentsShadow(
    legacyUserId: number,
    roles: Array<{ identityUserId: string; legacyUserId: number; roleName: string; source: string }>
  ) {
    this.roleAssignments.set(
      legacyUserId,
      roles.map((role) => ({
        ...role,
        status: "shadow",
        observedAt: "2026-06-10T00:00:00.000Z"
      }))
    );
    return roles.length;
  }

  async replaceOrganizationMembershipsShadow(
    legacyUserId: number,
    organizations: Array<{
      identityUserId: string;
      legacyUserId: number;
      organizationId: number;
      organizationRole: string | null;
      source: string;
      metadata?: Record<string, unknown>;
    }>
  ) {
    this.organizationMemberships.set(
      legacyUserId,
      organizations.map((organization) => ({
        ...organization,
        status: "shadow",
        observedAt: "2026-06-10T00:00:00.000Z"
      }))
    );
    return organizations.length;
  }

  async createReconciliationRun(input: { runKey: string; scope: string; mode: string; metadata: Record<string, unknown> }) {
    this.runs.set(input.runKey, {
      runKey: input.runKey,
      scope: input.scope,
      mode: input.mode,
      status: "running",
      startedAt: "2026-06-10T00:00:00.000Z",
      finishedAt: null,
      sampleCount: 0,
      mismatchCount: 0,
      p0Count: 0,
      p1Count: 0,
      metadata: input.metadata
    });
    this.items.set(input.runKey, []);
  }

  async insertReconciliationItems(items: any[]) {
    for (const item of items) {
      const list = this.items.get(item.runKey) ?? [];
      list.push({
        ...item,
        createdAt: "2026-06-10T00:00:00.000Z"
      });
      this.items.set(item.runKey, list);
    }
    return items.length;
  }

  async finishReconciliationRun(input: {
    runKey: string;
    status: "succeeded" | "failed";
    sampleCount: number;
    mismatchCount: number;
    p0Count: number;
    p1Count: number;
    metadata: Record<string, unknown>;
  }) {
    const current = this.runs.get(input.runKey);
    this.runs.set(input.runKey, {
      ...current,
      status: input.status,
      finishedAt: "2026-06-10T00:00:01.000Z",
      sampleCount: input.sampleCount,
      mismatchCount: input.mismatchCount,
      p0Count: input.p0Count,
      p1Count: input.p1Count,
      metadata: input.metadata
    });
  }

  async getReconciliationRun(runKey: string) {
    return this.runs.get(runKey) ?? null;
  }

  async listRecentReconciliationRuns(limit = 10) {
    return [...this.runs.values()].slice(-limit).reverse();
  }

  async listReconciliationItems(runKey: string) {
    return this.items.get(runKey) ?? [];
  }

  async summarizeReconciliationItems(runKey: string) {
    const items = this.items.get(runKey) ?? [];
    return {
      p0: items.filter((item) => item.severity === "p0").length,
      p1: items.filter((item) => item.severity === "p1").length,
      p2: items.filter((item) => item.severity === "p2").length,
      info: items.filter((item) => item.severity === "info").length
    };
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

class FakeOidcAuthorizationCodeRepository {
  readonly codes = new Map<
    string,
    {
      id: number;
      clientId: string;
      redirectUri: string;
      legacyUserId: number;
      username: string | null;
      scope: string;
      codeChallenge: string;
      codeChallengeMethod: "S256";
      nonce: string | null;
      authTime: Date;
      expiresAt: Date;
      consumedAt: Date | null;
    }
  >();
  nextId = 1;

  isConfigured() {
    return true;
  }

  async issue(input: {
    clientId: string;
    redirectUri: string;
    legacyUserId: number;
    username: string | null;
    scope: string;
    codeChallenge: string;
    codeChallengeMethod: "S256";
    nonce: string | null;
    authTime: Date;
    expiresAt: Date;
  }) {
    const code = `oidc-code-${this.nextId}`;
    const record = {
      id: this.nextId,
      ...input,
      consumedAt: null
    };
    this.nextId += 1;
    this.codes.set(code, record);

    return {
      ...input,
      code,
      codeHash: `hash-${code}`
    };
  }

  async consume(input: { code: string; clientId: string; redirectUri: string }) {
    const record = this.codes.get(input.code);
    if (
      !record ||
      record.clientId !== input.clientId ||
      record.redirectUri !== input.redirectUri ||
      record.consumedAt ||
      record.expiresAt.getTime() <= Date.now()
    ) {
      throw new InvalidAuthorizationCodeError();
    }

    record.consumedAt = new Date();

    return {
      ...record
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

class FakeUsageBillingRepository {
  configured = true;
  readonly events: LoginAuditSourceEvent[] = [];
  readonly ledger = new Map<string, UsageLedgerRecord>();
  readonly runs = new Map<string, UsageReplayRunRow>();
  readonly balances = new Map<string, { includedQuota: number; usedQuantity: number; remainingQuantity: number }>();

  isConfigured() {
    return this.configured;
  }

  async listSuccessfulLoginEvents(input: { afterId: number; limit: number }) {
    return this.events.filter((event) => event.id > input.afterId && event.success && event.eventType === "login").slice(0, input.limit);
  }

  async insertLedger(record: UsageLedgerRecord) {
    if (this.ledger.has(record.ledgerKey)) {
      return { duplicate: true };
    }

    this.ledger.set(record.ledgerKey, record);
    return { duplicate: false };
  }

  async createReplayRun(input: { runKey: string; mode: string; metadata: Record<string, unknown> }) {
    this.runs.set(input.runKey, {
      runKey: input.runKey,
      mode: input.mode,
      status: "running",
      startedAt: new Date().toISOString(),
      finishedAt: null,
      processedCount: 0,
      createdCount: 0,
      skippedCount: 0,
      metadata: input.metadata
    });
  }

  async finishReplayRun(input: {
    runKey: string;
    status: "succeeded" | "failed";
    processedCount: number;
    createdCount: number;
    skippedCount: number;
    metadata: Record<string, unknown>;
  }) {
    const current = this.runs.get(input.runKey);
    this.runs.set(input.runKey, {
      runKey: input.runKey,
      mode: current?.mode ?? "apply",
      status: input.status,
      startedAt: current?.startedAt ?? new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      processedCount: input.processedCount,
      createdCount: input.createdCount,
      skippedCount: input.skippedCount,
      metadata: input.metadata
    });
  }

  async rebuildShadowBalances(input: { includedQuota: number; billingCycle: string }) {
    this.balances.clear();
    for (const record of this.ledger.values()) {
      if (record.billingStatus !== "shadow") {
        continue;
      }
      const key = `${record.subjectType}:${record.subjectId}:${record.usageType}`;
      const current = this.balances.get(key) ?? {
        includedQuota: input.includedQuota,
        usedQuantity: 0,
        remainingQuantity: input.includedQuota
      };
      current.usedQuantity += record.quantity;
      current.remainingQuantity = input.includedQuota - current.usedQuantity;
      this.balances.set(key, current);
    }

    return this.balances.size;
  }

  async getBalance(subjectType: string, subjectId: string, usageType = "login") {
    const balance = this.balances.get(`${subjectType}:${subjectId}:${usageType}`);
    return balance
      ? {
          subjectType,
          subjectId,
          usageType,
          includedQuota: balance.includedQuota,
          usedQuantity: balance.usedQuantity,
          remainingQuantity: balance.remainingQuantity,
          billingCycle: "default",
          updatedAt: new Date().toISOString()
        }
      : null;
  }

  async listLedger() {
    return [...this.ledger.values()].map((record) => ({
      ledgerKey: record.ledgerKey,
      sourceEventId: record.sourceEventId,
      subjectType: record.subjectType,
      subjectId: record.subjectId,
      usageType: record.usageType,
      quantity: record.quantity,
      unit: record.unit,
      chargeMode: record.chargeMode,
      billingStatus: record.billingStatus,
      occurredAt: record.occurredAt.toISOString(),
      createdAt: new Date().toISOString(),
      metadata: record.metadata
    }));
  }

  async getReplayRun(runKey: string) {
    return this.runs.get(runKey) ?? null;
  }

  async getLoginUsageReport() {
    const records = [...this.ledger.values()].filter((record) => record.usageType === "login");
    return {
      totalLedgerRecords: records.length,
      freeLoginRecords: records.filter((record) => record.chargeMode === "free").length,
      billableLoginRecords: records.filter((record) => record.chargeMode === "billable").length,
      shadowRecords: records.filter((record) => record.billingStatus === "shadow").length,
      usedQuantity: records.reduce((total, record) => total + record.quantity, 0)
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
    expect(response.body.capabilities.oidc).toBe("disabled");
  });

  it("returns safe empty JWKS by default", async () => {
    const response = await request(app.getHttpServer()).get("/jwks.json").expect(200);

    expect(response.body).toEqual({ keys: [] });
  });

  it("publishes safe OIDC discovery while stage 8 endpoints stay disabled by default", async () => {
    const discovery = await request(app.getHttpServer()).get("/.well-known/openid-configuration").expect(200);

    expect(discovery.body).toMatchObject({
      issuer: "identity-service",
      authorization_endpoint: "identity-service/authorize",
      token_endpoint: "identity-service/token",
      userinfo_endpoint: "identity-service/userinfo",
      jwks_uri: "identity-service/jwks.json",
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      xrugc_stage: "identity-oidc-standardization",
      xrugc_capabilities: {
        enabled: false,
        authorizationEndpoint: "disabled",
        tokenEndpoint: "disabled",
        logoutEndpoint: "disabled",
        pkceRequired: true,
        legacyAuthFallbackRequired: true,
        identityPrimaryCutoverAllowed: false
      }
    });

    await request(app.getHttpServer()).get("/authorize").expect(503);
    await request(app.getHttpServer()).post("/token").expect(503);
    await request(app.getHttpServer()).get("/logout").expect(503);
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

  it("rejects non-identity bearer tokens on userinfo", async () => {
    await request(app.getHttpServer())
      .get("/userinfo")
      .set("Authorization", "Bearer legacy-token")
      .expect(401);
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

  it("keeps IAM readonly views disabled by default", async () => {
    const readiness = await request(app.getHttpServer()).get("/internal/iam/readiness").expect(200);

    expect(readiness.body.data).toMatchObject({
      enabled: false,
      mode: "disabled",
      views: {
        user: false,
        role: false,
        permission: false,
        organization: false,
        plugin: false
      }
    });

    await request(app.getHttpServer()).get("/internal/iam/users/24").expect(404);
  });
});

describe("identity-adapter OIDC standardization API", () => {
  let app: INestApplication;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";
    process.env.IDENTITY_OIDC_ENABLED = "true";
    process.env.IDENTITY_OIDC_ISSUER = "https://identity.example.com";
    process.env.IDENTITY_OIDC_CLIENTS_JSON = JSON.stringify([
      {
        clientId: "xrugc-web",
        enabled: true,
        type: "public",
        redirectUris: ["https://xrugc.com/oidc/callback"],
        scopes: ["openid", "profile", "email"],
        requirePkce: true
      },
      {
        clientId: "admin-console",
        enabled: false,
        type: "confidential",
        redirectUris: ["https://admin.xrugc.com/oidc/callback"],
        scopes: ["openid", "profile", "roles"],
        clientSecret: "admin-secret",
        adminMfaRequired: true
      }
    ]);

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
    process.env = { ...originalEnv };
    await app.close();
  });

  it("reports internal OIDC readiness without exposing client secrets", async () => {
    await request(app.getHttpServer()).get("/internal/oidc/readiness").expect(401);

    const response = await request(app.getHttpServer())
      .get("/internal/oidc/readiness")
      .set("x-identity-internal-token", "test-internal-token")
      .expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      capability: "oidc",
      data: {
        enabled: true,
        issuer: "https://identity.example.com",
        endpoints: {
          discovery: "enabled",
          authorization: "disabled",
          token: "disabled",
          userinfo: "identity-token-only",
          jwks: "enabled",
          logout: "disabled"
        },
        clients: {
          configured: 2,
          enabled: 1,
          entries: [
            {
              clientId: "xrugc-web",
              enabled: true,
              type: "public",
              redirectUriCount: 1,
              scopes: ["openid", "profile", "email"],
              requirePkce: true,
              adminMfaRequired: false
            },
            {
              clientId: "admin-console",
              enabled: false,
              type: "confidential",
              redirectUriCount: 1,
              scopes: ["openid", "profile", "roles"],
              requirePkce: true,
              adminMfaRequired: true,
              clientSecretConfigured: true
            }
          ]
        },
        stores: {
          authorizationCode: "not_configured",
          ttlSeconds: 300
        },
        safety: {
          authorizationCodePkceRequired: true,
          legacyAuthFallbackRequired: true,
          identityPrimaryCutoverAllowed: false,
          accountLifecycleRemainsLegacyCompatible: true,
          adminMfaRequired: false
        }
      }
    });
    expect(JSON.stringify(response.body)).not.toContain("admin-secret");
  });

  it("keeps authorization and token exchange unavailable until explicitly enabled", async () => {
    const authorize = await request(app.getHttpServer()).get("/authorize").query({
      response_type: "code",
      client_id: "xrugc-web",
      redirect_uri: "https://xrugc.com/oidc/callback",
      scope: "openid profile",
      state: "state-1",
      code_challenge: "challenge",
      code_challenge_method: "S256"
    });
    expect(authorize.status).toBe(503);
    expect(authorize.body.code).toBe("OIDC_ENDPOINT_DISABLED");

    const token = await request(app.getHttpServer()).post("/token").send({
      grant_type: "authorization_code",
      code: "code",
      code_verifier: "verifier"
    });
    expect(token.status).toBe(503);
    expect(token.body.code).toBe("OIDC_ENDPOINT_DISABLED");
  });
});

describe("identity-adapter OIDC request-host issuer", () => {
  let app: INestApplication;
  const originalEnv = { ...process.env };

  beforeEach(async () => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_OIDC_ISSUER_MODE = "request-host";
    process.env.IDENTITY_OIDC_ISSUER_SCHEME = "https";
    process.env.IDENTITY_OIDC_ALLOWED_ISSUER_HOSTS = "identity.d.xrteeth.com,identity.d.tmrpp.com";

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
    process.env = { ...originalEnv };
    await app.close();
  });

  it("publishes discovery from the allowlisted request host only", async () => {
    const xrteeth = await request(app.getHttpServer())
      .get("/.well-known/openid-configuration")
      .set("Host", "identity.d.xrteeth.com")
      .expect(200);

    expect(xrteeth.body).toMatchObject({
      issuer: "https://identity.d.xrteeth.com",
      authorization_endpoint: "https://identity.d.xrteeth.com/authorize",
      token_endpoint: "https://identity.d.xrteeth.com/token"
    });

    const tmrpp = await request(app.getHttpServer())
      .get("/.well-known/openid-configuration")
      .set("Host", "identity.d.xrteeth.com")
      .set("X-Forwarded-Host", "identity.d.tmrpp.com")
      .expect(200);

    expect(tmrpp.body).toMatchObject({
      issuer: "https://identity.d.tmrpp.com",
      jwks_uri: "https://identity.d.tmrpp.com/jwks.json"
    });

    const rejected = await request(app.getHttpServer())
      .get("/.well-known/openid-configuration")
      .set("Host", "evil.example.com")
      .expect(400);

    expect(rejected.body.code).toBe("OIDC_ISSUER_HOST_NOT_ALLOWED");
  });
});

describe("identity-adapter OIDC authorization code + PKCE API", () => {
  let app: INestApplication;
  let sessions: FakeIdentitySessionRepository;
  let codes: FakeOidcAuthorizationCodeRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const redirectUri = "https://xrugc.com/oidc/callback";
  const codeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

  beforeEach(async () => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "oidc-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-api";
    process.env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS = "3600";
    process.env.IDENTITY_REFRESH_TOKEN_TTL_SECONDS = "604800";
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";
    process.env.IDENTITY_OIDC_ENABLED = "true";
    process.env.IDENTITY_OIDC_ISSUER = "https://identity.example.com";
    process.env.IDENTITY_OIDC_AUTHORIZATION_ENDPOINT_ENABLED = "true";
    process.env.IDENTITY_OIDC_TOKEN_ENDPOINT_ENABLED = "true";
    process.env.IDENTITY_OIDC_LOGOUT_ENDPOINT_ENABLED = "true";
    process.env.IDENTITY_OIDC_AUTHORIZATION_CODE_TTL_SECONDS = "300";
    process.env.IDENTITY_OIDC_CLIENTS_JSON = JSON.stringify([
      {
        clientId: "xrugc-web",
        enabled: true,
        type: "public",
        redirectUris: [redirectUri],
        postLogoutRedirectUris: ["https://xrugc.com/logout/callback"],
        scopes: ["openid", "profile", "email", "roles", "organization", "offline_access"],
        requirePkce: true
      },
      {
        clientId: "admin-console",
        enabled: true,
        type: "confidential",
        redirectUris: ["https://admin.xrugc.com/oidc/callback"],
        postLogoutRedirectUris: ["https://admin.xrugc.com/logout/callback"],
        scopes: ["openid", "profile", "roles"],
        clientSecret: "admin-secret",
        adminMfaRequired: true
      }
    ]);

    sessions = new FakeIdentitySessionRepository();
    codes = new FakeOidcAuthorizationCodeRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(IdentitySessionRepository)
      .useValue(sessions)
      .overrideProvider(OidcAuthorizationCodeRepository)
      .useValue(codes)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app.close();
  });

  it("exchanges an allowlisted authorization code with PKCE and keeps the code single-use", async () => {
    const login = await loginAs(app, "guanfei");
    const challenge = pkceChallenge(codeVerifier);

    const authorize = await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid profile email roles organization offline_access",
        state: "state-1",
        nonce: "nonce-1",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(302);

    const callback = new URL(authorize.headers.location);
    expect(callback.origin + callback.pathname).toBe(redirectUri);
    expect(callback.searchParams.get("state")).toBe("state-1");
    const code = callback.searchParams.get("code");
    expect(code).toEqual(expect.stringMatching(/^oidc-code-/));
    expect(codes.codes.get(code!)?.codeChallenge).toBe(challenge);

    const token = await request(app.getHttpServer())
      .post("/token")
      .send({
        grant_type: "authorization_code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        code,
        code_verifier: codeVerifier
      })
      .expect(200);

    expect(token.body).toMatchObject({
      token_type: "Bearer",
      expires_in: expect.any(Number),
      refresh_token: "refresh-2",
      scope: "openid profile email roles organization offline_access"
    });
    expect(token.body.access_token).toEqual(expect.any(String));
    expect(token.body.id_token).toEqual(expect.any(String));

    const idTokenPayload = decodeJwtPayload(token.body.id_token);
    expect(idTokenPayload).toMatchObject({
      iss: "https://identity.example.com",
      aud: "xrugc-web",
      sub: "24",
      nonce: "nonce-1",
      preferred_username: "guanfei",
      email: "ogre3d@163.com",
      email_verified: true,
      roles: ["admin"]
    });
    expect(idTokenPayload.organization).toEqual([{ id: 1, name: "test-university", title: "测试大学" }]);

    await request(app.getHttpServer())
      .post("/token")
      .send({
        grant_type: "authorization_code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        code,
        code_verifier: codeVerifier
      })
      .expect(400);
  });

  it("rejects unsafe authorization requests before issuing a code", async () => {
    const login = await loginAs(app, "guanfei");
    const challenge = pkceChallenge(codeVerifier);

    await request(app.getHttpServer())
      .get("/authorize")
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid profile",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(401);

    await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: "https://evil.example.com/callback",
        scope: "openid profile",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(400);

    await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid admin",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(400);

    expect(codes.codes.size).toBe(0);
  });

  it("supports JSON response mode for the frontend OIDC bridge", async () => {
    const login = await loginAs(app, "guanfei");
    const challenge = pkceChallenge(codeVerifier);

    const authorize = await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        response_mode: "json",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid profile",
        state: "json-state",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(200);

    expect(authorize.body).toEqual({
      code: expect.stringMatching(/^oidc-code-/),
      state: "json-state",
      redirect_uri: redirectUri
    });
  });

  it("rejects an invalid PKCE verifier during token exchange", async () => {
    const login = await loginAs(app, "guanfei");
    const authorize = await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid profile",
        code_challenge: pkceChallenge(codeVerifier),
        code_challenge_method: "S256"
      })
      .expect(302);
    const code = new URL(authorize.headers.location).searchParams.get("code");

    const response = await request(app.getHttpServer())
      .post("/token")
      .send({
        grant_type: "authorization_code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        code,
        code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-wrong"
      })
      .expect(400);

    expect(response.body.code).toBe("INVALID_GRANT");
  });

  it("rotates OIDC refresh tokens through the token endpoint", async () => {
    const login = await loginAs(app, "guanfei");
    const challenge = pkceChallenge(codeVerifier);
    const authorize = await request(app.getHttpServer())
      .get("/authorize")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .query({
        response_type: "code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        scope: "openid offline_access",
        code_challenge: challenge,
        code_challenge_method: "S256"
      })
      .expect(302);
    const code = new URL(authorize.headers.location).searchParams.get("code");

    const token = await request(app.getHttpServer())
      .post("/token")
      .send({
        grant_type: "authorization_code",
        client_id: "xrugc-web",
        redirect_uri: redirectUri,
        code,
        code_verifier: codeVerifier
      })
      .expect(200);

    const refreshed = await request(app.getHttpServer())
      .post("/token")
      .send({
        grant_type: "refresh_token",
        client_id: "xrugc-web",
        refresh_token: token.body.refresh_token
      })
      .expect(200);

    expect(refreshed.body).toMatchObject({
      token_type: "Bearer",
      refresh_token: "refresh-3"
    });
  });

  it("handles OIDC logout with a strict post logout redirect allowlist", async () => {
    const login = await loginAs(app, "guanfei");

    const logout = await request(app.getHttpServer())
      .get("/logout")
      .query({
        client_id: "xrugc-web",
        post_logout_redirect_uri: "https://xrugc.com/logout/callback",
        state: "bye"
      })
      .expect(302);

    const redirect = new URL(logout.headers.location);
    expect(redirect.origin + redirect.pathname).toBe("https://xrugc.com/logout/callback");
    expect(redirect.searchParams.get("state")).toBe("bye");

    await request(app.getHttpServer())
      .get("/logout")
      .query({
        client_id: "xrugc-web",
        post_logout_redirect_uri: "https://evil.example.com/logout"
      })
      .expect(400);

    const response = await request(app.getHttpServer())
      .post("/logout")
      .send({
        client_id: "xrugc-web",
        post_logout_redirect_uri: "https://xrugc.com/logout/callback",
        refresh_token: login.refreshToken
      })
      .expect(200);

    expect(response.body).toMatchObject({
      success: true,
      message: "logout",
      redirectUrl: "https://xrugc.com/logout/callback"
    });
    expect(sessions.sessions.get(login.refreshToken)?.revokedAt).toBeInstanceOf(Date);
  });
});

describe("identity-adapter IAM readonly API", () => {
  let app: INestApplication;
  let iamRepository: FakeIamRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(async () => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_IAM_ENABLED = "true";
    process.env.IDENTITY_IAM_MODE = "readonly";
    process.env.IDENTITY_IAM_INTERNAL_API_TOKEN = "iam-test-token";
    process.env.IDENTITY_IAM_USER_VIEW_ENABLED = "true";
    process.env.IDENTITY_IAM_ROLE_VIEW_ENABLED = "true";
    process.env.IDENTITY_IAM_PERMISSION_VIEW_ENABLED = "true";
    process.env.IDENTITY_IAM_ORGANIZATION_VIEW_ENABLED = "true";
    process.env.IDENTITY_IAM_PLUGIN_VIEW_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "iam-readonly-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-iam-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-iam";
    iamRepository = new FakeIamRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(IamRepository)
      .useValue(iamRepository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app.close();
  });

  it("reports IAM readiness without changing write modes", async () => {
    const readiness = await request(app.getHttpServer()).get("/internal/iam/readiness").expect(200);

    expect(readiness.body.data).toMatchObject({
      enabled: true,
      mode: "readonly",
      fallbackEnabled: true,
      identityRepositoryConfigured: true,
      views: {
        user: true,
        role: true,
        permission: true,
        organization: true,
        plugin: true
      },
      writes: {
        profile: "disabled",
        role: "disabled",
        organization: "disabled",
        pluginUser: "disabled"
      }
    });
  });

  it("requires the internal token for IAM data views", async () => {
    await request(app.getHttpServer()).get("/internal/iam/users/24").expect(401);
  });

  it("returns user, role, permission and organization views from readonly sources", async () => {
    const headers = { "x-identity-internal-token": "iam-test-token" };
    const user = await request(app.getHttpServer()).get("/internal/iam/users/24").set(headers).expect(200);
    const roles = await request(app.getHttpServer()).get("/internal/iam/users/24/roles").set(headers).expect(200);
    const permissions = await request(app.getHttpServer()).get("/internal/iam/users/24/permissions").set(headers).expect(200);
    const organizations = await request(app.getHttpServer()).get("/internal/iam/users/24/organizations").set(headers).expect(200);

    expect(user.body.data).toMatchObject({
      identityUserId: "id-user-24",
      legacyUserId: 24,
      keycloakSubject: "keycloak-subject-24",
      username: "guanfei",
      source: {
        profile: "legacy",
        identityMap: "identity-db"
      }
    });
    expect(roles.body.data.roles).toEqual([{ name: "admin", source: "legacy-yii-rbac" }]);
    expect(roles.body.data.shadow).toHaveLength(1);
    expect(permissions.body.data.permissions.map((permission: { name: string }) => permission.name)).toEqual([
      "course.manage",
      "plugin.open"
    ]);
    expect(organizations.body.data.organizations).toEqual([
      {
        id: 1,
        name: "test-university",
        title: "测试大学",
        createdAt: 1,
        updatedAt: 1,
        source: "legacy"
      }
    ]);
    expect(organizations.body.data.shadow).toHaveLength(1);
  });

  it("returns plugin identity views from identity JWT and legacy profile", async () => {
    const legacyUser = await new FakeLegacyIdentityReader().getUserById(24);
    expect(legacyUser).not.toBeNull();
    const token = new JwtIssuerService().issue(legacyUser!, "session-24").accessToken;
    const response = await request(app.getHttpServer())
      .post("/internal/iam/plugin/verify-token")
      .set("x-identity-internal-token", "iam-test-token")
      .send({ token })
      .expect(201);

    expect(response.body.data).toMatchObject({
      valid: true,
      user: {
        uid: 24,
        username: "guanfei",
        roles: ["admin"],
        sessionId: "session-24"
      },
      source: {
        token: "identity-jwt",
        profile: "legacy"
      }
    });
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

  it("proxies WeChat QR login polling through the register lifecycle scope", async () => {
    process.env.IDENTITY_ACCOUNT_REGISTER_ENABLED = "true";
    app = await createLifecycleTestApp();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            qrcode: { url: "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=ticket" },
            token: "wechat-token",
            lifetime: 518400
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            success: true,
            message: "signin",
            token: "wechat-token"
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      );
    vi.stubGlobal("fetch", fetchMock);

    const qrcode = await request(app.getHttpServer()).get("/v1/wechat/qrcode").expect(200);
    expect(qrcode.body).toEqual({
      qrcode: { url: "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=ticket" },
      token: "wechat-token",
      lifetime: 518400
    });

    const refresh = await request(app.getHttpServer()).get("/v1/wechat/refresh?token=wechat-token").expect(200);
    expect(refresh.body).toEqual({
      success: true,
      message: "signin",
      token: "wechat-token"
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [qrcodeUrl, qrcodeInit] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    const [refreshUrl, refreshInit] = fetchMock.mock.calls[1] as unknown as [URL, RequestInit];
    expect(qrcodeUrl.toString()).toBe("http://legacy-api/v1/wechat/qrcode");
    expect(refreshUrl.toString()).toBe("http://legacy-api/v1/wechat/refresh?token=wechat-token");
    expect(qrcodeInit.body).toBeUndefined();
    expect(refreshInit.body).toBeUndefined();
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

describe("identity-adapter plugin user write legacy-proxy API", () => {
  let app: INestApplication | null = null;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE = "legacy-proxy";
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_LEGACY_API_BASE_URL = "http://legacy-api";
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_TIMEOUT_MS = "5000";
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("keeps plugin-user write endpoints disabled by default", async () => {
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE = "disabled";
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .send({ username: "new-user", password: "Secret123!" })
      .expect(404);

    expect(response.body).toMatchObject({
      code: "PLUGIN_USER_WRITE_DISABLED",
      message: "Plugin user write migration is disabled."
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports the legacy-proxy posture without requiring public exposure", async () => {
    app = await createLifecycleTestApp();

    const response = await request(app.getHttpServer())
      .get("/internal/plugin-user-write/readiness")
      .expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      capability: "plugin-user-write",
      data: {
        enabled: true,
        mode: "legacy-proxy",
        legacyProxyConfigured: true,
        operationLedgerSchemaAutoEnsure: false,
        idempotencyKeyFormat: "plugin-user-write:v1:<route>:<sha256-48>",
        redactionPolicy: "metadata-only-no-secret-payloads",
        compensationRecordsRequired: true,
        shadow: {
          enabled: false,
          mode: "off",
          sideEffect: "none",
          responseShapePreserved: true,
          legacyProxyRequired: true
        },
        allowedExecutableModes: ["disabled", "legacy-proxy"],
        unsupportedModeBlocked: false,
        dualWriteSupported: false,
        identityNativeSupported: false,
        nextRequiredSpec: "identity-plugin-user-native-write",
        sourceOfTruth: "legacy"
      }
    });
    expect(response.body.data.blockedReasons).toEqual([]);
    expect(response.body.data.routes).toEqual(
      expect.arrayContaining(["create-user", "update-user", "delete-user", "change-role", "batch-create-users"])
    );
    expect(typeof response.body.data.operationLedgerConfigured).toBe("boolean");
    expect(response.body.data.requiredBeforeDualWrite).toEqual(
      expect.arrayContaining(["operation-ledger", "idempotency-keys", "compensation-records"])
    );
    expect(response.body.data.requiredBeforeIdentityNative).toEqual(
      expect.arrayContaining(["clean-dual-write-production-evidence", "legacy-proxy-rollback-window"])
    );
  });

  it("does not execute unsupported write modes", async () => {
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE = "dual-write";
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const readiness = await request(app.getHttpServer())
      .get("/internal/plugin-user-write/readiness")
      .expect(200);

    expect(readiness.body.data).toMatchObject({
      enabled: true,
      mode: "dual-write",
      sourceOfTruth: "unsupported",
      unsupportedModeBlocked: true,
      dualWriteSupported: false,
      identityNativeSupported: false,
      nextRequiredSpec: "identity-plugin-user-native-write"
    });
    expect(readiness.body.data.blockedReasons).toEqual(
      expect.arrayContaining([expect.stringContaining("identity-plugin-user-native-write")])
    );

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .send({ username: "new-user", password: "Secret123!" })
      .expect(404);

    expect(response.body).toMatchObject({
      code: "PLUGIN_USER_WRITE_UNSUPPORTED_MODE"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("prepares stable operation keys and redacts plugin-user write evidence", () => {
    const leftFingerprint = pluginUserWriteRequestFingerprint("create-user", {
      username: "stage-user",
      email: "stage@example.com",
      password: "Secret123!",
      profile: {
        token: "token-value",
        nickname: "Stage"
      }
    });
    const rightFingerprint = pluginUserWriteRequestFingerprint("create-user", {
      profile: {
        nickname: "Stage",
        token: "another-token-value"
      },
      password: "AnotherSecret123!",
      email: "stage@example.com",
      username: "stage-user"
    });

    expect(leftFingerprint).toBe(rightFingerprint);

    const key = pluginUserWriteOperationKey({
      route: "create-user",
      actorSubject: "legacy-user:24",
      targetSubject: "username:stage-user",
      requestFingerprint: leftFingerprint
    });
    expect(key).toMatch(/^plugin-user-write:v1:create-user:[a-f0-9]{48}$/);

    const redacted = redactPluginUserWriteMetadata({
      username: "stage-user",
      password: "Secret123!",
      nested: {
        refreshToken: "secret-refresh-token",
        authorization: "Bearer secret"
      }
    });
    expect(redacted).toEqual({
      username: "stage-user",
      password: "[redacted]",
      nested: {
        refreshToken: "[redacted]",
        authorization: "[redacted]"
      }
    });
    expect(JSON.stringify(redacted)).not.toContain("Secret123!");
    expect(JSON.stringify(redacted)).not.toContain("secret-refresh-token");
  });

  it("requires an explicit legacy API base URL before legacy-proxy writes", async () => {
    delete process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_LEGACY_API_BASE_URL;
    delete process.env.IDENTITY_ACCOUNT_LIFECYCLE_LEGACY_API_BASE_URL;
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .send({ username: "new-user", password: "Secret123!" })
      .expect(503);

    expect(response.body).toMatchObject({
      code: "PLUGIN_USER_WRITE_LEGACY_API_NOT_CONFIGURED"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("proxies privileged user writes without changing status or response shape", async () => {
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ code: 0, data: { id: 42, username: "new-user" } }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .set("Authorization", "Bearer operator-token")
      .set("X-Forwarded-For", "10.0.0.2")
      .set("User-Agent", "Vitest")
      .send({
        username: "new-user",
        nickname: "New User",
        password: "Secret123!",
        organization_ids: [1, 2]
      })
      .expect(201);

    expect(response.headers["x-identity-plugin-user-write"]).toBe("legacy-proxy");
    expect(response.body).toEqual({ code: 0, data: { id: 42, username: "new-user" } });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.toString()).toBe("http://legacy-api/v1/plugin-user/create-user");
    const headers = init.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer operator-token");
    expect(headers.get("X-Forwarded-For")).toBe("10.0.0.2");
    expect(headers.get("User-Agent")).toBe("Vitest");
    expect(headers.get("X-Identity-Plugin-User-Write-Proxy")).toBe("1");
    expect(JSON.parse(String(init.body))).toEqual({
      username: "new-user",
      nickname: "New User",
      password: "Secret123!",
      organization_ids: [1, 2]
    });
  });

  it("keeps shadow writer off by default during legacy-proxy writes", async () => {
    const operations = new FakePluginUserWriteOperationRepository();
    app = await createLifecycleTestApp(operations);
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ code: 0, data: { id: 42, username: "new-user" } }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .send({ username: "new-user", password: "Secret123!" })
      .expect(201);

    expect(response.body).toEqual({ code: 0, data: { id: 42, username: "new-user" } });
    expect(operations.inputs).toHaveLength(0);
  });

  it("logs redacted plan-mode shadow evidence for all plugin-user write routes without writing the ledger", async () => {
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE = "plan";
    const logSpy = vi.spyOn(Logger.prototype, "log").mockImplementation(() => undefined);
    const operations = new FakePluginUserWriteOperationRepository();
    app = await createLifecycleTestApp(operations);
    const fetchMock = vi.fn(async (url: URL | string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      const pathname = typeof url === "string" ? new URL(url).pathname : url.pathname;
      const status = body.id || pathname.endsWith("/batch-create-users") ? 200 : 201;
      return new Response(JSON.stringify({ code: 0, data: { id: body.id ?? 42, username: body.username ?? "new-user" } }), {
        status,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    try {
      const createResponse = await request(app.getHttpServer())
        .post("/v1/plugin-user/create-user")
        .set("Authorization", "Bearer test-token")
        .send({ username: "new-user", password: "Secret123!" })
        .expect(201);

      await request(app.getHttpServer())
        .post("/v1/plugin-user/update-user")
        .set("Authorization", "Bearer test-token")
        .send({ id: 42, nickname: "Updated User", password: "Secret456!" })
        .expect(200);

      await request(app.getHttpServer())
        .post("/v1/plugin-user/delete-user")
        .set("Authorization", "Bearer test-token")
        .send({ id: 42 })
        .expect(200);

      await request(app.getHttpServer())
        .post("/v1/plugin-user/change-role")
        .set("Authorization", "Bearer test-token")
        .send({ id: 42, role: "admin" })
        .expect(200);

      await request(app.getHttpServer())
        .post("/v1/plugin-user/batch-create-users")
        .set("Authorization", "Bearer test-token")
        .send({
          users: [
            {
              username: "batch-user-001",
              nickname: "Batch User 001",
              password: "BatchSecret123!",
              role: "user",
              status: 10
            }
          ]
        })
        .expect(200);

      expect(createResponse.body).toEqual({ code: 0, data: { id: 42, username: "new-user" } });
      expect(operations.inputs).toHaveLength(0);
      const logPayloads = logSpy.mock.calls
        .map(([message]) => String(message))
        .filter((message) => message.includes("identity.plugin_user.write.shadow"));
      expect(logPayloads).toHaveLength(5);
      expect(logPayloads.some((payload) => payload.includes('"route":"create-user"'))).toBe(true);
      expect(logPayloads.some((payload) => payload.includes('"route":"update-user"'))).toBe(true);
      expect(logPayloads.some((payload) => payload.includes('"route":"delete-user"'))).toBe(true);
      expect(logPayloads.some((payload) => payload.includes('"route":"change-role"'))).toBe(true);
      expect(logPayloads.some((payload) => payload.includes('"route":"batch-create-users"'))).toBe(true);
      for (const logPayload of logPayloads) {
        expect(logPayload).toContain('"mode":"plan"');
        expect(logPayload).toContain('"sideEffect":"none"');
        expect(logPayload).not.toContain("Secret123!");
        expect(logPayload).not.toContain("Secret456!");
        expect(logPayload).not.toContain("BatchSecret123!");
        expect(logPayload).not.toContain("batch-user-001");
        expect(logPayload).not.toContain("test-token");
      }
    } finally {
      logSpy.mockRestore();
    }
  });

  it("records ledger-only shadow evidence without changing the legacy-proxy response", async () => {
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_SHADOW_MODE = "ledger-only";
    const operations = new FakePluginUserWriteOperationRepository();
    app = await createLifecycleTestApp(operations);
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ code: 0, data: { id: 42, username: "new-user" } }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/create-user")
      .set("Authorization", "Bearer test-token")
      .send({ username: "new-user", password: "Secret123!" })
      .expect(201);

    expect(response.body).toEqual({ code: 0, data: { id: 42, username: "new-user" } });
    expect(response.headers["x-identity-plugin-user-write"]).toBe("legacy-proxy");
    expect(operations.inputs).toHaveLength(1);
    expect(operations.inputs[0]).toMatchObject({
      route: "create-user",
      mode: "dual-write",
      actorSubject: "authorization:present",
      targetSubject: "username:new-user"
    });
    expect(operations.inputs[0].operationKey).toMatch(/^plugin-user-write:v1:create-user:[a-f0-9]{48}$/);
    expect(operations.inputs[0].idempotencyKey).toBe(operations.inputs[0].operationKey);
    expect(JSON.stringify(operations.inputs[0].metadata)).not.toContain("Secret123!");
    expect(JSON.stringify(operations.inputs[0].metadata)).not.toContain("test-token");
  });

  it("preserves legacy validation errors so callers do not repeat writes", async () => {
    app = await createLifecycleTestApp();
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ code: 4004, message: "用户不存在" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await request(app.getHttpServer())
      .post("/v1/plugin-user/update-user")
      .set("Authorization", "Bearer operator-token")
      .send({ id: 404, nickname: "missing" })
      .expect(404);

    expect(response.headers["x-identity-plugin-user-write"]).toBe("legacy-proxy");
    expect(response.body).toEqual({ code: 4004, message: "用户不存在" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("identity-adapter plugin user readonly compatibility API", () => {
  let app: INestApplication | null = null;
  let repository: FakeIdentitySessionRepository;
  const originalEnv = { ...process.env };
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.IDENTITY_TOKEN_ISSUANCE_ENABLED = "true";
    process.env.IDENTITY_JWT_PRIVATE_KEY_PEM = privateKeyPem;
    process.env.IDENTITY_JWT_KEY_ID = "plugin-user-readonly-test-key";
    process.env.IDENTITY_JWT_ISSUER = "identity-plugin-user-test";
    process.env.IDENTITY_JWT_AUDIENCE = "xrugc-plugin-user";
    process.env.IDENTITY_ACCESS_TOKEN_TTL_SECONDS = "3600";
    process.env.IDENTITY_REFRESH_TOKEN_TTL_SECONDS = "604800";
    repository = new FakeIdentitySessionRepository();
  });

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
    app = null;
  });

  it("keeps the readonly compatibility endpoint disabled by default", async () => {
    app = await createPluginUserReadonlyTestApp(repository);
    await request(app.getHttpServer())
      .get("/v1/plugin-user/users?page=1&pageSize=1")
      .expect(404);
  });

  it("returns the old user list response shape when enabled", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    app = await createPluginUserReadonlyTestApp(repository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?page=1&pageSize=1&search=guan&sort=id&order=asc")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      data: [
        {
          id: 24,
          username: "guanfei",
          nickname: "babamama",
          roles: ["admin"]
        }
      ],
      pagination: {
        page: 1,
        pageSize: 1,
        total: 1,
        totalPages: 1
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy");
  });

  it("returns the old user detail response shape when enabled", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    app = await createPluginUserReadonlyTestApp(repository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=25")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        id: 25,
        username: "unverified",
        nickname: "unverified",
        roles: ["user"]
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy");
  });

  it("keeps shadow-compare non-user-facing and returns the legacy response", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "shadow-compare";
    const iamRepository = new FakeIamRepository();
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?page=1&pageSize=1&search=guan&sort=id&order=asc")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      data: [
        {
          id: 24,
          username: "guanfei",
          nickname: "babamama",
          roles: ["admin"]
        }
      ],
      pagination: {
        page: 1,
        pageSize: 1,
        total: 1,
        totalPages: 1
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy");
  });

  it("uses identity-db for allowlisted plugin-user reads", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    const iamRepository = new FakeIamRepository();
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=24")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        id: 24,
        username: "guanfei",
        nickname: "babamama",
        roles: ["admin"],
        organizations: [{ id: 1, name: "test-university", title: "测试大学" }]
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("identity-db");
  });

  it("keeps plugin-user reads on legacy while plugin-user writes are legacy-proxy", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    process.env.IDENTITY_IAM_PLUGIN_USER_WRITE_MODE = "legacy-proxy";
    const iamRepository = new FakeIamRepository();
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?page=1&pageSize=1&search=guan&sort=id&order=asc")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      data: [
        {
          id: 24,
          username: "guanfei",
          nickname: "babamama",
          roles: ["admin"]
        }
      ],
      pagination: {
        page: 1,
        pageSize: 1,
        total: 1,
        totalPages: 1
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy");
  });

  it("logs safe identity-db primary-read decisions for plugin-user reads", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    const logSpy = vi.spyOn(Logger.prototype, "log").mockImplementation(() => undefined);
    const iamRepository = new FakeIamRepository();
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    try {
      await request(app.getHttpServer())
        .get("/v1/plugin-user/users?page=1&pageSize=1&search=guan&sort=id&order=asc")
        .set("Authorization", `Bearer ${login.accessToken}`)
        .expect(200);

      const message = logSpy.mock.calls
        .map((call) => String(call[0] ?? ""))
        .find((item) => item.includes("identity.plugin_user.primary_read.decision"));

      expect(message).toBeTruthy();
      expect(message).not.toContain(login.accessToken);
      expect(message).not.toContain("Bearer ");

      const payload = JSON.parse(message!);
      expect(payload).toMatchObject({
        event: "identity.plugin_user.primary_read.decision",
        scope: "plugin-user.users.list",
        readMode: "allowlist",
        source: "identity-db",
        fallbackAttempted: false,
        fallbackUsed: false,
        fallbackBlocked: false,
        fallbackControlMode: "off",
        fallbackControlReason: "control_off",
        fallbackReason: null,
        subjectId: "uid:24"
      });
    } finally {
      logSpy.mockRestore();
    }
  });

  it("falls back to legacy when allowlisted identity-db reads miss the user", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    const iamRepository = new FakeIamRepository();
    iamRepository.identityUsers.delete(24);
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=24")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        id: 24,
        username: "guanfei",
        nickname: "babamama",
        roles: ["admin"]
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy-fallback");
  });

  it("blocks fallback only for selected canary subjects", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_CONTROL_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_MODE = "canary";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_ALLOWLIST = "username:guanfei";
    const warnSpy = vi.spyOn(Logger.prototype, "warn").mockImplementation(() => undefined);
    const iamRepository = new FakeIamRepository();
    iamRepository.identityUsers.delete(24);
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    try {
      const response = await request(app.getHttpServer())
        .get("/v1/plugin-user/users?id=24")
        .set("Authorization", `Bearer ${login.accessToken}`)
        .expect(503);

      expect(response.body).toMatchObject({
        code: "PLUGIN_USER_PRIMARY_READ_UNAVAILABLE",
        fallbackControlMode: "canary",
        fallbackControlReason: "canary_subject_selected"
      });
      expect(String(warnSpy.mock.calls.at(-1)?.[0] ?? "")).toContain("identity.plugin_user.primary_read.fallback_blocked");
      expect(String(warnSpy.mock.calls.at(-1)?.[0] ?? "")).not.toContain(login.accessToken);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("keeps fallback for canary-control subjects that are not selected", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_CONTROL_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_MODE = "canary";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_ALLOWLIST = "username:not-guanfei";
    const iamRepository = new FakeIamRepository();
    iamRepository.identityUsers.delete(24);
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=24")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        id: 24,
        username: "guanfei",
        nickname: "babamama",
        roles: ["admin"]
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy-fallback");
  });

  it("blocks fallback for selected percentage buckets independently from primary-read percentage", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_CONTROL_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_MODE = "percentage";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_PERCENTAGE = "100";
    const iamRepository = new FakeIamRepository();
    iamRepository.identityUsers.delete(24);
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=24")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(503);

    expect(response.body).toMatchObject({
      code: "PLUGIN_USER_PRIMARY_READ_UNAVAILABLE",
      fallbackControlMode: "percentage",
      fallbackControlReason: "percentage_bucket_selected"
    });
  });

  it("restores fallback when fallback-control mode is off", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_MODE = "allowlist";
    process.env.IDENTITY_PLUGIN_USER_PRIMARY_READ_ALLOWLIST = "uid:24";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_CONTROL_ENABLED = "true";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_MODE = "off";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_ALLOWLIST = "username:guanfei";
    process.env.IDENTITY_PLUGIN_USER_FALLBACK_DISABLE_PERCENTAGE = "100";
    const iamRepository = new FakeIamRepository();
    iamRepository.identityUsers.delete(24);
    app = await createPluginUserReadonlyTestApp(repository, iamRepository);
    const login = await loginAs(app, "guanfei");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?id=24")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(200);

    expect(response.body).toMatchObject({
      code: 0,
      data: {
        id: 24,
        username: "guanfei",
        nickname: "babamama",
        roles: ["admin"]
      }
    });
    expect(response.headers["x-identity-user-source"]).toBe("legacy-fallback");
  });

  it("rejects non-elevated users without the legacy plugin permission", async () => {
    process.env.IDENTITY_PLUGIN_USER_READONLY_ENABLED = "true";
    app = await createPluginUserReadonlyTestApp(repository);
    const login = await loginAs(app, "unverified");

    const response = await request(app.getHttpServer())
      .get("/v1/plugin-user/users?page=1&pageSize=1")
      .set("Authorization", `Bearer ${login.accessToken}`)
      .expect(403);

    expect(response.body).toMatchObject({
      code: 2003,
      message: "没有权限执行此操作"
    });
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

  it("does not issue a token when a completed native standard registration is retried with a different password", async () => {
    await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "retry-user@example.com", password: "R3gister!234" })
      .expect(201);

    const response = await request(app!.getHttpServer())
      .post("/v1/auth/register")
      .send({ username: "retry-user@example.com", password: "Different!234" })
      .expect(400);

    expect(response.body).toMatchObject({
      username: ['Username "retry-user@example.com" has already been taken.'],
      message: "username already exists"
    });
    expect(response.body.token).toBeUndefined();
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

  it("does not issue a token when a completed native wechat registration is retried with a different password", async () => {
    await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "wechat-token", username: "wechat-retry@example.com", password: "R3gister!234" })
      .expect(200);

    const response = await request(app!.getHttpServer())
      .post("/v1/wechat/register")
      .send({ token: "wechat-token", username: "wechat-retry@example.com", password: "Different!234" })
      .expect(400);

    expect(response.text).toContain("already registered,1000");
    expect(response.body.token).toBeUndefined();
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

async function createLifecycleTestApp(
  pluginUserOperations?: FakePluginUserWriteOperationRepository
): Promise<INestApplication> {
  let builder = Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader);

  if (pluginUserOperations) {
    builder = builder.overrideProvider(PluginUserWriteOperationRepository).useValue(pluginUserOperations);
  }

  const moduleRef = await builder.compile();

  const lifecycleApp = moduleRef.createNestApplication();
  await lifecycleApp.init();

  return lifecycleApp;
}

async function createPluginUserReadonlyTestApp(
  repository: FakeIdentitySessionRepository,
  iamRepository?: FakeIamRepository
): Promise<INestApplication> {
  let builder = Test.createTestingModule({
    imports: [AppModule]
  })
    .overrideProvider(LegacyIdentityReader)
    .useClass(FakeLegacyIdentityReader)
    .overrideProvider(IdentitySessionRepository)
    .useValue(repository);

  if (iamRepository) {
    builder = builder.overrideProvider(IamRepository).useValue(iamRepository);
  }

  const moduleRef = await builder.compile();

  const pluginUserApp = moduleRef.createNestApplication();
  await pluginUserApp.init();

  return pluginUserApp;
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
    process.env.IDENTITY_INTERNAL_API_TOKEN = "test-internal-token";

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

    const userinfo = await request(app.getHttpServer())
      .get("/userinfo")
      .set("Authorization", `Bearer ${response.body.token.accessToken}`)
      .expect(200);

    expect(userinfo.body).toEqual({
      sub: "24",
      uid: 24,
      preferred_username: "guanfei",
      roles: ["admin"]
    });
  });

  it("rejects wrong passwords without issuing a refresh session", async () => {
    await request(app.getHttpServer())
      .post("/v1/auth/login")
      .send({ username: "guanfei", password: "wrong" })
      .expect(401);

    expect(repository.sessions.size).toBe(0);
  });

  it("issues an internal user token that can be refreshed by QR login clients", async () => {
    const issued = await request(app.getHttpServer())
      .post("/internal/auth/issue-user-token")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
      .set("User-Agent", "UnityQRLogin/1.0")
      .send({ legacyUserId: 24 })
      .expect(201);

    expect(issued.body).toMatchObject({
      success: true,
      message: "login",
      token: {
        tokenType: "Bearer",
        refreshToken: "refresh-1"
      }
    });

    const refresh = await request(app.getHttpServer())
      .post("/v1/auth/refresh")
      .send({ refreshToken: issued.body.token.refreshToken })
      .expect(201);

    expect(refresh.body.message).toBe("refresh");
    expect(refresh.body.token.refreshToken).toBe("refresh-2");
  });

  it("rejects internal user token issuance without the internal token", async () => {
    await request(app.getHttpServer())
      .post("/internal/auth/issue-user-token")
      .send({ legacyUserId: 24 })
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

describe("identity-adapter usage billing shadow API", () => {
  let app: INestApplication;
  let repository: FakeUsageBillingRepository;
  const originalEnv = { ...process.env };

  async function createApp(env: Record<string, string | undefined> = {}) {
    process.env = {
      ...originalEnv,
      IDENTITY_INTERNAL_API_TOKEN: "test-internal-token",
      IDENTITY_USAGE_BILLING_INTERNAL_API_TOKEN: "test-internal-token",
      IDENTITY_USAGE_BILLING_SHADOW_ENABLED: "false",
      IDENTITY_USAGE_BILLING_DRY_RUN: "true",
      IDENTITY_USAGE_BILLING_LOGIN_RULE: "successful-login-v1",
      IDENTITY_USAGE_BILLING_FREE_LOGIN_QUOTA: "1",
      IDENTITY_USAGE_BILLING_SUBJECT_STRATEGY: "user",
      IDENTITY_USAGE_BILLING_REPLAY_BATCH_SIZE: "500",
      IDENTITY_DB_HOST: "identity-mysql",
      IDENTITY_DB_USER: "identity",
      ...env
    };

    repository = new FakeUsageBillingRepository();
    repository.events.push(
      {
        id: 1,
        eventKey: "login-event-1",
        legacyUserId: 24,
        identityUserId: null,
        username: "guanfei",
        eventType: "login",
        success: true,
        occurredAt: new Date("2026-06-10T01:00:00.000Z"),
        source: "identity-service"
      },
      {
        id: 2,
        eventKey: "login-event-2",
        legacyUserId: 24,
        identityUserId: null,
        username: "guanfei",
        eventType: "login",
        success: true,
        occurredAt: new Date("2026-06-10T02:00:00.000Z"),
        source: "identity-service"
      },
      {
        id: 3,
        eventKey: "failed-login-event",
        legacyUserId: 24,
        identityUserId: null,
        username: "guanfei",
        eventType: "login",
        success: false,
        occurredAt: new Date("2026-06-10T03:00:00.000Z"),
        source: "identity-service"
      }
    );

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(UsageBillingRepository)
      .useValue(repository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  }

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
  });

  it("requires the internal service token", async () => {
    await createApp();

    await request(app.getHttpServer()).post("/internal/usage-billing/replay").send({ dryRun: true }).expect(401);
  });

  it("allows dry-run while shadow billing is disabled and does not write ledger records", async () => {
    await createApp({
      IDENTITY_USAGE_BILLING_SHADOW_ENABLED: "false",
      IDENTITY_USAGE_BILLING_DRY_RUN: "true"
    });

    const response = await request(app.getHttpServer())
      .post("/internal/usage-billing/replay")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send({ dryRun: true, afterId: 0, limit: 10, runKey: "dry-run-usage-billing" })
      .expect(201);

    expect(response.body.data).toMatchObject({
      runKey: "dry-run-usage-billing",
      dryRun: true,
      shadowEnabled: false,
      nonBilling: true,
      summary: {
        processedEvents: 2,
        plannedLedgerRecords: 2,
        createdLedgerRecords: 0,
        skippedEvents: 0,
        freeLoginRecords: 1,
        billableLoginRecords: 1
      }
    });
    expect(response.body.data.plannedRecords).toHaveLength(2);
    expect(repository.ledger.size).toBe(0);
    expect(repository.runs.size).toBe(0);
  });

  it("refuses apply mode while shadow billing is disabled", async () => {
    await createApp({
      IDENTITY_USAGE_BILLING_SHADOW_ENABLED: "false",
      IDENTITY_USAGE_BILLING_DRY_RUN: "false"
    });

    await request(app.getHttpServer())
      .post("/internal/usage-billing/replay")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send({ dryRun: false, runKey: "apply-disabled" })
      .expect(404);

    expect(repository.ledger.size).toBe(0);
  });

  it("applies shadow ledger records idempotently and rebuilds balance", async () => {
    await createApp({
      IDENTITY_USAGE_BILLING_SHADOW_ENABLED: "true",
      IDENTITY_USAGE_BILLING_DRY_RUN: "false"
    });

    const first = await request(app.getHttpServer())
      .post("/internal/usage-billing/replay")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send({ dryRun: false, runKey: "apply-shadow-1", afterId: 0, limit: 10, rebuildBalance: true })
      .expect(201);

    expect(first.body.data.summary).toMatchObject({
      processedEvents: 2,
      plannedLedgerRecords: 2,
      createdLedgerRecords: 2,
      duplicateLedgerRecords: 0,
      rebuiltBalances: 1
    });

    const second = await request(app.getHttpServer())
      .post("/internal/usage-billing/replay")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .send({ dryRun: false, runKey: "apply-shadow-2", afterId: 0, limit: 10, rebuildBalance: true })
      .expect(201);

    expect(second.body.data.summary).toMatchObject({
      createdLedgerRecords: 0,
      duplicateLedgerRecords: 2,
      rebuiltBalances: 1
    });
    expect(repository.ledger.size).toBe(2);

    const balance = await request(app.getHttpServer())
      .get("/internal/usage-billing/subjects/user/legacy:24/balance")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(balance.body.data).toMatchObject({
      subjectType: "user",
      subjectId: "legacy:24",
      usageType: "login",
      includedQuota: 1,
      usedQuantity: 2,
      remainingQuantity: -1
    });

    const run = await request(app.getHttpServer())
      .get("/internal/usage-billing/runs/apply-shadow-2")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(run.body.data).toMatchObject({
      runKey: "apply-shadow-2",
      mode: "apply",
      status: "succeeded",
      processedCount: 2,
      createdCount: 0,
      skippedCount: 2
    });

    const report = await request(app.getHttpServer())
      .get("/internal/usage-billing/reports/login-usage")
      .set("X-Identity-Internal-Token", "test-internal-token")
      .expect(200);

    expect(report.body.data).toMatchObject({
      totalLedgerRecords: 2,
      freeLoginRecords: 1,
      billableLoginRecords: 1,
      shadowRecords: 2,
      usedQuantity: 2,
      shadow: true,
      nonBilling: true
    });
  });
});

describe("identity-adapter IAM reconciliation API", () => {
  let app: INestApplication;
  let iamRepository: FakeIamRepository;
  const originalEnv = { ...process.env };

  async function createApp(env: Record<string, string | undefined> = {}) {
    process.env = {
      ...originalEnv,
      IDENTITY_IAM_ENABLED: "true",
      IDENTITY_IAM_MODE: "shadow",
      IDENTITY_IAM_INTERNAL_API_TOKEN: "iam-test-token",
      IDENTITY_IAM_USER_VIEW_ENABLED: "true",
      IDENTITY_IAM_ROLE_VIEW_ENABLED: "true",
      IDENTITY_IAM_PERMISSION_VIEW_ENABLED: "true",
      IDENTITY_IAM_ORGANIZATION_VIEW_ENABLED: "true",
      IDENTITY_IAM_PLUGIN_VIEW_ENABLED: "true",
      IDENTITY_IAM_RECONCILIATION_ENABLED: "false",
      IDENTITY_IAM_RECONCILIATION_BATCH_SIZE: "5",
      IDENTITY_DB_HOST: "identity-mysql",
      IDENTITY_DB_USER: "identity",
      ...env
    };
    iamRepository = new FakeIamRepository();

    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .overrideProvider(IamRepository)
      .useValue(iamRepository)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  }

  afterEach(async () => {
    process.env = { ...originalEnv };
    await app?.close();
  });

  it("allows dry-run reconciliation while writes are disabled", async () => {
    await createApp();

    const response = await request(app.getHttpServer())
      .post("/internal/iam/reconciliation/run")
      .set("x-identity-internal-token", "iam-test-token")
      .send({ dryRun: true, runKey: "iam-dry-run-25", scopes: ["user", "permission"], legacyUserIds: [25] })
      .expect(201);

    expect(response.body.data).toMatchObject({
      runKey: "iam-dry-run-25",
      dryRun: true,
      reconciliationEnabled: false,
      summary: {
        sampledUsers: 1,
        p1Count: 1,
        infoCount: 1,
        shadowWriteCount: 0
      },
      safetyGate: {
        passed: false
      }
    });
    expect(response.body.data.items).toHaveLength(2);
    expect(iamRepository.runs.size).toBe(0);
  });

  it("reports stage 7 reconciliation status before a succeeded baseline exists", async () => {
    await createApp();

    const response = await request(app.getHttpServer())
      .get("/internal/iam/reconciliation/status")
      .set("x-identity-internal-token", "iam-test-token")
      .expect(200);

    expect(response.body.data).toMatchObject({
      stage: "7",
      capability: "identity-iam-data-reconciliation",
      nonUserFacing: true,
      readiness: {
        enabled: true,
        mode: "shadow",
        reconciliationEnabled: false,
        schemaReady: true,
        writeModesDisabled: true,
        usageBillingDryRun: true
      },
      safetyGate: {
        passed: false,
        baselinePassed: false,
        canRunDryRun: true,
        canApplyShadow: false,
        canCutoverIdentityPrimary: false
      },
      lastSucceededRun: null,
      nextRecommendedAction: "run_small_dry_run_baseline"
    });
    expect(response.body.data.blockers).toContain("no_succeeded_reconciliation_baseline");
  });

  it("ensures IAM schema through an internal endpoint", async () => {
    await createApp();
    iamRepository.schemaTablesReady = false;

    const response = await request(app.getHttpServer())
      .post("/internal/iam/schema/ensure")
      .set("x-identity-internal-token", "iam-test-token")
      .expect(201);

    expect(iamRepository.schemaEnsureCount).toBe(1);
    expect(response.body.data).toMatchObject({
      identityDatabase: "configured",
      diagnostics: {
        identityDatabaseConfigured: true,
        tables: {
          identity_users: true,
          identity_subject_maps: true,
          identity_role_assignments_shadow: true,
          identity_organization_memberships_shadow: true,
          iam_reconciliation_runs: true,
          iam_reconciliation_items: true
        }
      },
      nonUserFacing: true
    });
  });

  it("refuses shadow apply while reconciliation is disabled", async () => {
    await createApp();

    await request(app.getHttpServer())
      .post("/internal/iam/reconciliation/run")
      .set("x-identity-internal-token", "iam-test-token")
      .send({ dryRun: false, runKey: "iam-apply-disabled", scopes: ["user"], legacyUserIds: [25] })
      .expect(404);

    expect(iamRepository.identityUsers.has(25)).toBe(false);
    expect(iamRepository.runs.size).toBe(0);
  });

  it("applies IAM shadow snapshots idempotently and reports the safety gate", async () => {
    await createApp({ IDENTITY_IAM_RECONCILIATION_ENABLED: "true" });

    const first = await request(app.getHttpServer())
      .post("/internal/iam/reconciliation/run")
      .set("x-identity-internal-token", "iam-test-token")
      .send({
        dryRun: false,
        runKey: "iam-apply-25",
        scopes: ["user", "role", "organization", "plugin"],
        legacyUserIds: [25]
      })
      .expect(201);

    expect(first.body.data).toMatchObject({
      runKey: "iam-apply-25",
      dryRun: false,
      applyShadow: true,
      summary: {
        sampledUsers: 1,
        mismatchCount: 0,
        p0Count: 0,
        p1Count: 0
      },
      safetyGate: {
        passed: true
      }
    });
    expect(first.body.data.batch).toMatchObject({
      explicitLegacyUserIds: [25],
      maxLegacyUserId: 25,
      nextAfterLegacyUserId: null
    });
    expect(iamRepository.identityUsers.get(25)).toMatchObject({
      id: "legacy:25",
      username: "unverified",
      status: "active"
    });
    expect(iamRepository.roleAssignments.get(25)).toHaveLength(1);
    expect(iamRepository.subjectMaps.get("legacy:25")?.filter((subject) => subject.subjectType === "plugin_user")).toHaveLength(1);

    const second = await request(app.getHttpServer())
      .post("/internal/iam/reconciliation/run")
      .set("x-identity-internal-token", "iam-test-token")
      .send({
        dryRun: false,
        runKey: "iam-apply-25-repeat",
        scopes: ["user", "role", "organization", "plugin"],
        legacyUserIds: [25]
      })
      .expect(201);

    expect(second.body.data.summary).toMatchObject({
      mismatchCount: 0,
      p0Count: 0,
      p1Count: 0
    });
    expect(iamRepository.roleAssignments.get(25)).toHaveLength(1);
    expect(iamRepository.subjectMaps.get("legacy:25")?.filter((subject) => subject.subjectType === "plugin_user")).toHaveLength(1);

    const report = await request(app.getHttpServer())
      .get("/internal/iam/reconciliation/runs/iam-apply-25")
      .set("x-identity-internal-token", "iam-test-token")
      .expect(200);

    expect(report.body.data).toMatchObject({
      run: {
        runKey: "iam-apply-25",
        status: "succeeded",
        sampleCount: 1,
        mismatchCount: 0
      },
      safetyGate: {
        passed: true
      },
      items: []
    });

    expect(report.body.data.run.metadata).toMatchObject({
      phase: "7",
      migrationStage: "identity-iam-data-reconciliation",
      batch: {
        explicitLegacyUserIds: [25],
        maxLegacyUserId: 25,
        nextAfterLegacyUserId: null
      }
    });

    const status = await request(app.getHttpServer())
      .get("/internal/iam/reconciliation/status")
      .set("x-identity-internal-token", "iam-test-token")
      .expect(200);

    expect(status.body.data).toMatchObject({
      stage: "7",
      safetyGate: {
        passed: true,
        baselinePassed: true,
        canApplyShadow: true,
        canCutoverIdentityPrimary: false
      },
      lastSucceededRun: {
        runKey: "iam-apply-25-repeat",
        status: "succeeded",
        sampleCount: 1,
        mismatchCount: 0,
        p0Count: 0,
        p1Count: 0,
        p2Count: 0,
        infoCount: 0,
        safetyGatePassed: true
      },
      nextRecommendedAction: "expand_next_reconciliation_batch_with_cursor"
    });
    expect(status.body.data.blockers).toEqual([]);
    expect(status.body.data.recentRuns).toHaveLength(2);
  });

  it("records cursor metadata for stage 7 reconciliation batches", async () => {
    await createApp({ IDENTITY_IAM_RECONCILIATION_ENABLED: "true" });

    const response = await request(app.getHttpServer())
      .post("/internal/iam/reconciliation/run")
      .set("x-identity-internal-token", "iam-test-token")
      .send({
        dryRun: false,
        runKey: "iam-apply-cursor-25",
        scopes: ["user"],
        afterLegacyUserId: 24,
        limit: 1
      })
      .expect(201);

    expect(response.body.data).toMatchObject({
      runKey: "iam-apply-cursor-25",
      batch: {
        explicitLegacyUserIds: null,
        afterLegacyUserId: 24,
        requestedLimit: 1,
        sampledLegacyUserIds: [25],
        maxLegacyUserId: 25,
        nextAfterLegacyUserId: 25
      }
    });

    const report = await request(app.getHttpServer())
      .get("/internal/iam/reconciliation/runs/iam-apply-cursor-25")
      .set("x-identity-internal-token", "iam-test-token")
      .expect(200);

    expect(report.body.data.run.metadata).toMatchObject({
      phase: "7",
      migrationStage: "identity-iam-data-reconciliation",
      batch: {
        afterLegacyUserId: 24,
        nextAfterLegacyUserId: 25
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

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}
