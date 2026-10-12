import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { verifyImportedAccessToken } from "./legacy-token-verifier.js";
import { loadConfig } from "./config.js";
import type { LegacyUserReadModel } from "./legacy-identity.reader.js";
import { assertDeviceSnAccount, deviceSnClaims, deviceSnSource, type DeviceSnSource } from "./device-sn-source.js";

export interface IssuedAccessToken {
  accessToken: string;
  expiresAt: Date;
  jwtId: string;
}

export interface VerifiedAccessToken {
  uid: number;
  username: string | null;
  sessionId: string | null;
  roles: string[];
  importedLegacy?: boolean;
  authMethod?: "device_sn";
  deviceSnId?: number;
}

export interface OidcIdTokenInput {
  user: LegacyUserReadModel;
  issuer: string;
  audience: string;
  authTime: Date;
  nonce?: string | null;
  scope?: string[];
  expiresInSeconds?: number;
}

@Injectable()
export class JwtIssuerService {
  private readonly config = loadConfig();
  assertSigningReady():void {
    const privateKey=this.privateKey(), publicKey=this.publicKey();
    if(privateKey.asymmetricKeyType!=="ec" || privateKey.asymmetricKeyDetails?.namedCurve!=="prime256v1")throw new Error("Identity signing key must use P-256");
    const derived=createPublicKey(privateKey).export({format:"jwk"});const actual=publicKey.export({format:"jwk"});
    if(derived.x!==actual.x || derived.y!==actual.y)throw new Error("Identity signing key pair does not match");
  }

  issue(user: LegacyUserReadModel, sessionId: string, options?: { audience?: string; scopes?: string[]; expiresInSeconds?: number } & Partial<DeviceSnSource>): IssuedAccessToken {
    const source = deviceSnSource(options?.authMethod, options?.deviceSnId);
    if (source) assertDeviceSnAccount(user);
    const now = new Date();
    const configuredTtl = options?.expiresInSeconds ?? this.config.tokenIssuance.accessTokenTtlSeconds;
    const expiresAt = new Date(now.getTime() + (source ? Math.min(10800, configuredTtl) : configuredTtl) * 1000);
    const jwtId = randomId();
    const privateKey = this.privateKey();

    const header = {
      alg: "ES256",
      typ: "JWT",
      kid: this.config.jwt.keyId
    };
    const payload: Record<string, unknown> = {
      iss: this.config.jwt.issuer,
      sub: String(user.id),
      uid: user.id,
      username: user.username,
      roles: user.roles,
      session_id: sessionId,
      token_use: "access",
      jti: jwtId,
      iat: seconds(now),
      nbf: seconds(now),
      exp: seconds(expiresAt)
    };

    const audience = options?.audience ?? this.config.jwt.audience;
    if (audience) {
      payload.aud = audience;
    }
    if (options?.scopes) payload.scope = options.scopes.join(" ");
    if (source) { payload.auth_method = source.authMethod; payload.device_sn_id = source.deviceSnId; }

    const signingInput = `${base64urlJson(header)}.${base64urlJson(payload)}`;
    const signature = sign("sha256", Buffer.from(signingInput), {
      key: privateKey,
      dsaEncoding: "ieee-p1363"
    });

    return {
      accessToken: `${signingInput}.${signature.toString("base64url")}`,
      expiresAt,
      jwtId
    };
  }

  issueOidcIdToken(input: OidcIdTokenInput): IssuedAccessToken {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (input.expiresInSeconds ?? this.config.tokenIssuance.accessTokenTtlSeconds) * 1000);
    const jwtId = randomId();
    const privateKey = this.privateKey();
    const scopes = new Set(input.scope ?? []);

    const header = {
      alg: "ES256",
      typ: "JWT",
      kid: this.config.jwt.keyId
    };
    const payload: Record<string, unknown> = {
      iss: input.issuer,
      sub: String(input.user.id),
      aud: input.audience,
      exp: seconds(expiresAt),
      iat: seconds(now),
      auth_time: seconds(input.authTime),
      jti: jwtId
    };

    if (input.nonce) {
      payload.nonce = input.nonce;
    }
    if (scopes.has("profile")) {
      payload.preferred_username = input.user.username;
      payload.name = input.user.nickname ?? input.user.username;
    }
    if (scopes.has("email")) {
      payload.email = input.user.email;
      payload.email_verified = Boolean(input.user.emailVerifiedAt);
    }
    if (scopes.has("roles")) {
      payload.roles = input.user.roles;
    }
    if (scopes.has("organization")) {
      payload.organization = input.user.organizations.map((organization) => ({
        id: organization.id,
        name: organization.name,
        title: organization.title
      }));
    }

    const signingInput = `${base64urlJson(header)}.${base64urlJson(payload)}`;
    const signature = sign("sha256", Buffer.from(signingInput), {
      key: privateKey,
      dsaEncoding: "ieee-p1363"
    });

    return {
      accessToken: `${signingInput}.${signature.toString("base64url")}`,
      expiresAt,
      jwtId
    };
  }

  jwks(): { keys: Record<string, unknown>[] } {
    try {
      const publicKey = this.publicKey();
      const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
      delete jwk.d;

      return {
        keys: [
          {
            ...jwk,
            kid: this.config.jwt.keyId,
            alg: "ES256",
            use: "sig"
          }
        ]
      };
    } catch {
      return { keys: [] };
    }
  }

  verifyAccessToken(token: string, options?: { audience: string }): VerifiedAccessToken {
    try { return this.verifyCurrentAccessToken(token, options); }
    catch (error) {
      if (this.config.dataSource !== "identity") throw error;
      const payload = verifyImportedAccessToken(token);
      if (options?.audience && payload.aud !== options.audience) throw new Error("invalid imported token audience");
      const uid = Number(payload.uid);
      if (!Number.isSafeInteger(uid) || uid <= 0) throw new Error("invalid token subject");
      const source = verifiedDeviceSource(payload);
      return { uid, username: typeof payload.username === "string" ? payload.username : null,
        sessionId: typeof payload.session_id === "string" ? payload.session_id : null, roles: [], importedLegacy: true, ...(source ?? {}) };
    }
  }

  private verifyCurrentAccessToken(token: string, options?: { audience: string }): VerifiedAccessToken {
    if (token.split(".").length !== 3) throw new Error("invalid token format");
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
      throw new Error("invalid token format");
    }

    const header = parseJwtPart(encodedHeader);
    if (header.alg !== "ES256") {
      throw new Error("unsupported token algorithm");
    }
    if (this.config.dataSource === "identity" && header.kid !== this.config.jwt.keyId) throw new Error("unrecognized signing key");

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = Buffer.from(encodedSignature, "base64url");
    const valid = verify("sha256", Buffer.from(signingInput), { key: this.publicKey(), dsaEncoding: "ieee-p1363" }, signature);
    if (!valid) {
      throw new Error("invalid token signature");
    }

    const payload = parseJwtPart(encodedPayload);
    const source = verifiedDeviceSource(payload);
    const now = seconds(new Date());
    if (this.config.dataSource === "identity" && (typeof payload.iat !== "number" || !Number.isFinite(payload.iat) || payload.iat > now + 10)) throw new Error("invalid token issue time");
    if (!Number.isFinite(payload.exp) || Number(payload.exp) <= now) {
      throw new Error("token expired");
    }
    if (typeof payload.nbf === "number" && payload.nbf > now) {
      throw new Error("token not active");
    }
    if (payload.iss !== this.config.jwt.issuer) {
      throw new Error("invalid token issuer");
    }
    const expectedAudience = options?.audience ?? this.config.jwt.audience;
    if (this.config.dataSource === "identity" && !expectedAudience && payload.aud != null) throw new Error("invalid token audience");
    if (expectedAudience && payload.aud !== expectedAudience) {
      throw new Error("invalid token audience");
    }

    const uid = Number(payload.uid ?? payload.sub);
    if (!Number.isInteger(uid) || uid <= 0) {
      throw new Error("invalid token subject");
    }
    if (this.config.dataSource === "identity" && (Number(payload.uid)!==uid || String(payload.sub)!==String(uid)
      || typeof payload.session_id!=="string" || !payload.session_id || (payload.token_use!=null && payload.token_use!=="access"))) throw new Error("invalid access token purpose");

    return {
      uid,
      username: typeof payload.username === "string" ? payload.username : null,
      sessionId: typeof payload.session_id === "string" ? payload.session_id : null,
      roles: Array.isArray(payload.roles) ? payload.roles.filter((role): role is string => typeof role === "string") : [],
      ...(source ?? {})
    };
  }

  private privateKey() {
    const pem = this.config.jwt.privateKeyPem ?? readOptionalFile(this.config.jwt.privateKeyFile);
    if (!pem) {
      throw new ServiceUnavailableException({
        code: "IDENTITY_JWT_PRIVATE_KEY_REQUIRED",
        message: "JWT private key is required before enabling identity token issuance."
      });
    }

    return createPrivateKey(pem);
  }

  private publicKey() {
    const publicPem = this.config.jwt.publicKeyPem ?? readOptionalFile(this.config.jwt.publicKeyFile);
    if (publicPem) {
      return createPublicKey(publicPem);
    }

    return createPublicKey(this.privateKey());
  }
}

function base64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function verifiedDeviceSource(payload: Record<string, unknown>): DeviceSnSource | null {
  const source = deviceSnClaims(payload);
  if (source && (typeof payload.exp !== "number" || typeof payload.iat !== "number" || !Number.isFinite(payload.exp)
    || !Number.isFinite(payload.iat) || payload.exp - payload.iat > 10800 || payload.exp <= payload.iat)) throw new Error("invalid device token lifetime");
  return source;
}

function parseJwtPart(value: string): Record<string, unknown> {
  const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("invalid token payload");
  }

  return parsed as Record<string, unknown>;
}

function seconds(value: Date): number {
  return Math.floor(value.getTime() / 1000);
}

function randomId(): string {
  return randomBytes(24).toString("base64url");
}

function readOptionalFile(path: string | undefined): string | undefined {
  if (!path) {
    return undefined;
  }

  return readFileSync(path, "utf8");
}
