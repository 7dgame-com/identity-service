import { createHash, randomBytes } from "node:crypto";
import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { IdentitySessionRepository, InvalidRefreshTokenError } from "./identity-session.repository.js";
import { JwtIssuerService } from "./jwt-issuer.service.js";
import { LegacyIdentityReader, LegacyUserReadModel } from "./legacy-identity.reader.js";
import { verifyLegacyPassword } from "./legacy-password.js";
import { LoginAuditService } from "./login-audit.service.js";
import type { PoolConnection, RowDataPacket } from "mysql2/promise";

const loginSchema = z.object({
  username: z.string().min(1).max(255),
  password: z.string().min(1).max(1024)
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1).max(4096)
});

const logoutSchema = z.object({
  refreshToken: z.string().min(1).max(4096).optional().nullable()
});

const issueUserTokenSchema = z.object({
  legacyUserId: z.coerce.number().int().positive()
});

export interface RequestContext {
  ip?: string | null;
  userAgent?: string | null;
  idempotencyKey?: string;
}

export interface AuthTokenResponse {
  success: true;
  message: "login" | "refresh" | "register";
  token: {
    token: string;
    accessToken: string;
    refreshToken: string;
    expires: string;
    tokenType: "Bearer";
  };
}

export interface TransactionalAuthResponse extends AuthTokenResponse { sessionId:string;refreshTokenHash:string; }

@Injectable()
export class TokenIssuanceService {
  private readonly config = loadConfig();

  constructor(
    private readonly legacyReader: LegacyIdentityReader,
    private readonly sessions: IdentitySessionRepository,
    private readonly jwtIssuer: JwtIssuerService,
    private readonly loginAudit: LoginAuditService
  ) {}

  async login(payload: unknown, context: RequestContext = {}): Promise<AuthTokenResponse> {
    this.assertEnabled();
    const parsed = parseBody(loginSchema, payload);

    const credential = await this.legacyReader.getUserCredentialByUsername(parsed.username);
    if (!credential?.passwordHash || !(await verifyLegacyPassword(parsed.password, credential.passwordHash))) {
      throw new UnauthorizedException({
        code: "INVALID_CREDENTIALS",
        message: "Username or password is invalid."
      });
    }

    const user = await this.requireLegacyUser(credential.id);
    const sessionId = randomId();
    const response = await this.issueForUser(user, sessionId, context, "login", credential.passwordHash);

    await this.recordLoginAudit(user, sessionId, context);

    return response;
  }

  async refresh(payload: unknown, context: RequestContext = {}): Promise<AuthTokenResponse> {
    this.assertEnabled();
    const parsed = parseBody(refreshSchema, payload);

    try {
      const current = await (typeof this.sessions.findRefreshCandidate === "function"
        ? this.sessions.findRefreshCandidate(parsed.refreshToken) : this.sessions.findValidSession(parsed.refreshToken));
      if (this.config.dataSource === "identity" && await this.sessions.isOAuthBound(current.sessionId)) throw new InvalidRefreshTokenError("OAuth refresh tokens must use their bound client");
      const user = await this.requireLegacyUser(current.legacyUserId);
      const nextSessionId = current.sessionId;
      const refreshExpiresAt = this.refreshExpiresAt();
      // Validate signing configuration before consuming a refresh token.
      this.jwtIssuer.issue(user, nextSessionId);
      const rotated = await this.sessions.rotate(parsed.refreshToken, {
        legacyUserId: user.id,
        username: user.username,
        sessionId: nextSessionId,
        expiresAt: refreshExpiresAt,
        ipAddressHash: hashMaybe(context.ip),
        userAgentHash: hashMaybe(context.userAgent)
      }, context.idempotencyKey);
      const token = this.jwtIssuer.issue(user, rotated.sessionId);

      return tokenResponse("refresh", token.accessToken, rotated.refreshToken, token.expiresAt);
    } catch (error) {
      if (error instanceof InvalidRefreshTokenError) {
        throw new UnauthorizedException({
          code: "REFRESH_TOKEN_INVALID",
          message: "Refresh token is invalid."
        });
      }
      throw error;
    }
  }

  async logout(payload: unknown): Promise<{ success: true; message: "logout"; revoked: boolean }> {
    this.assertEnabled();
    const parsed = parseBody(logoutSchema, payload ?? {});
    const revoked = await this.sessions.revoke(parsed.refreshToken);

    return { success: true, message: "logout", revoked };
  }

  async issueRegisteredUser(user: LegacyUserReadModel, context: RequestContext = {}, expectedPasswordHash?: string): Promise<AuthTokenResponse> {
    this.assertEnabled();
    const sessionId = randomId();

    return this.issueForUser(user, sessionId, context, "register", expectedPasswordHash);
  }

  async issueLegacyUserToken(payload: unknown, context: RequestContext = {}): Promise<AuthTokenResponse> {
    this.assertEnabled();
    const parsed = parseBody(issueUserTokenSchema, payload);
    const user = await this.requireLegacyUser(parsed.legacyUserId);
    const sessionId = randomId();

    return this.issueForUser(user, sessionId, context, "login");
  }

  async exchangeLegacyPhpSession(payload:unknown,context:RequestContext={}):Promise<AuthTokenResponse>{
    this.assertEnabled();
    if(this.config.dataSource!=="identity")throw new UnauthorizedException();
    const parsed=parseBody(z.object({userId:z.number().int().positive(),authKey:z.string().min(16).max(255)}),payload);
    const user=await this.requireLegacyUser(parsed.userId);
    return this.issueForUser(user,randomId(),context,"login",undefined,parsed.authKey);
  }

  async assertTransactionIssuanceReady():Promise<void>{
    this.assertEnabled();
    if(this.config.dataSource!=="identity"||!this.sessions.isConfigured())throw new BadRequestException("Private Identity session storage is required");
    this.jwtIssuer.assertSigningReady();
    await this.sessions.ensureSchema();
  }

  /** Consume the proof and create its session under the same private account transaction. */
  async issueInTransaction(connection:PoolConnection,userId:number,context:RequestContext={}):Promise<TransactionalAuthResponse>{
    this.assertEnabled();
    if(this.config.dataSource!=="identity")throw new UnauthorizedException();
    const [rows]=await connection.execute<RowDataPacket[]>("SELECT * FROM user WHERE id=? FOR UPDATE",[userId]);const row=rows[0];
    if(!row||Number(row.status)!==10||row.deleted_at!=null)throw new UnauthorizedException("Account is inactive");
    const [roles]=await connection.execute<RowDataPacket[]>(`SELECT aa.item_name AS name FROM auth_assignment aa
      JOIN auth_item ai ON ai.name=aa.item_name WHERE aa.user_id=? AND ai.type=1 ORDER BY aa.item_name`,[String(userId)]);
    const user:LegacyUserReadModel={id:userId,username:row.username??null,email:row.email??null,status:10,nickname:row.nickname??null,
      emailVerifiedAt:row.email_verified_at==null?null:Number(row.email_verified_at),createdAt:row.created_at==null?null:Number(row.created_at),
      updatedAt:row.updated_at==null?null:Number(row.updated_at),roles:roles.map(role=>String(role.name)),organizations:[],userInfo:null,source:"identity-db"};
    const sessionId=randomId(),access=this.jwtIssuer.issue(user,sessionId);
    const session=await this.sessions.issueInTransaction(connection,{legacyUserId:userId,username:user.username,sessionId,
      expiresAt:this.refreshExpiresAt(),expectedPasswordHash:row.password_hash??undefined,ipAddressHash:hashMaybe(context.ip),userAgentHash:hashMaybe(context.userAgent)});
    return {...tokenResponse("login",access.accessToken,session.refreshToken,access.expiresAt),sessionId,refreshTokenHash:session.refreshTokenHash};
  }

  private async issueForUser(
    user: LegacyUserReadModel,
    sessionId: string,
    context: RequestContext,
    message: "login" | "refresh" | "register",
    expectedPasswordHash?: string,
    expectedLegacyAuthKey?: string
  ): Promise<AuthTokenResponse> {
    if (!this.sessions.isConfigured()) {
      throw new BadRequestException({
        code: "IDENTITY_DB_NOT_CONFIGURED",
        message: "Identity database is required for token issuance."
      });
    }

    const token = this.jwtIssuer.issue(user, sessionId);
    const refreshExpiresAt = this.refreshExpiresAt();
    let session;
    try { session = await this.sessions.issue({
      legacyUserId: user.id,
      username: user.username,
      sessionId,
      expiresAt: refreshExpiresAt,
      ipAddressHash: hashMaybe(context.ip),
      userAgentHash: hashMaybe(context.userAgent),
      expectedPasswordHash,
      expectedLegacyAuthKey
    }); } catch (error) {
      if(error instanceof InvalidRefreshTokenError)throw new UnauthorizedException({code:"ACCOUNT_CHANGED",message:"Account credentials changed while authenticating"});
      throw error;
    }

    return tokenResponse(message, token.accessToken, session.refreshToken, token.expiresAt);
  }

  private async requireLegacyUser(id: number): Promise<LegacyUserReadModel> {
    const user = await this.legacyReader.getUserById(id);
    if (!user || user.status !== 10) {
      throw new UnauthorizedException({
        code: "LEGACY_USER_NOT_FOUND",
        message: "Legacy user was not found."
      });
    }

    return user;
  }

  private async recordLoginAudit(user: LegacyUserReadModel, sessionId: string, context: RequestContext): Promise<void> {
    if (!this.config.loginAudit.enabled) {
      return;
    }

    try {
      await this.loginAudit.record({
        eventKey: `identity-login:${user.id}:${sessionId}`,
        legacyUserId: user.id,
        username: user.username,
        eventType: "login",
        success: true,
        occurredAt: new Date().toISOString(),
        ipAddress: context.ip ?? null,
        userAgent: context.userAgent ?? null,
        source: "identity-adapter",
        traceId: sessionId,
        metadata: {
          provider: "identity"
        }
      });
    } catch {
      // Login audit remains bypass-only and must not block token issuance.
    }
  }

  private refreshExpiresAt(): Date {
    return new Date(Date.now() + this.config.tokenIssuance.refreshTokenTtlSeconds * 1000);
  }

  private assertEnabled(): void {
    if (!this.config.tokenIssuance.enabled) {
      throw new NotFoundException({
        code: "TOKEN_ISSUANCE_DISABLED",
        message: "Identity token issuance is disabled."
      });
    }
  }
}

function tokenResponse(
  message: "login" | "refresh" | "register",
  accessToken: string,
  refreshToken: string,
  expiresAt: Date
): AuthTokenResponse {
  return {
    success: true,
    message,
    token: {
      token: accessToken,
      accessToken,
      refreshToken,
      expires: expiresAt.toISOString(),
      tokenType: "Bearer"
    }
  };
}

function parseBody<T extends z.ZodTypeAny>(schema: T, payload: unknown): z.infer<T> {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new BadRequestException({
      code: "INVALID_AUTH_PAYLOAD",
      message: "Auth request payload is invalid.",
      details: parsed.error.flatten()
    });
  }

  return parsed.data;
}

function randomId(): string {
  return randomBytes(24).toString("base64url");
}

function hashMaybe(value: string | null | undefined): string | null {
  const normalized = value?.trim();
  if (!normalized) {
    return null;
  }

  return createHash("sha256").update(normalized).digest("hex");
}
