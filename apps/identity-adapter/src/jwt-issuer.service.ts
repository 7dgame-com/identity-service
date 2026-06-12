import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import type { LegacyUserReadModel } from "./legacy-identity.reader.js";

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

  issue(user: LegacyUserReadModel, sessionId: string): IssuedAccessToken {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.config.tokenIssuance.accessTokenTtlSeconds * 1000);
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
      jti: jwtId,
      iat: seconds(now),
      nbf: seconds(now),
      exp: seconds(expiresAt)
    };

    if (this.config.jwt.audience) {
      payload.aud = this.config.jwt.audience;
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

  verifyAccessToken(token: string): VerifiedAccessToken {
    const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
      throw new Error("invalid token format");
    }

    const header = parseJwtPart(encodedHeader);
    if (header.alg !== "ES256") {
      throw new Error("unsupported token algorithm");
    }

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = Buffer.from(encodedSignature, "base64url");
    const valid = verify("sha256", Buffer.from(signingInput), { key: this.publicKey(), dsaEncoding: "ieee-p1363" }, signature);
    if (!valid) {
      throw new Error("invalid token signature");
    }

    const payload = parseJwtPart(encodedPayload);
    const now = seconds(new Date());
    if (typeof payload.exp === "number" && payload.exp <= now) {
      throw new Error("token expired");
    }
    if (typeof payload.nbf === "number" && payload.nbf > now) {
      throw new Error("token not active");
    }
    if (payload.iss !== this.config.jwt.issuer) {
      throw new Error("invalid token issuer");
    }
    if (this.config.jwt.audience && payload.aud !== this.config.jwt.audience) {
      throw new Error("invalid token audience");
    }

    const uid = Number(payload.uid ?? payload.sub);
    if (!Number.isInteger(uid) || uid <= 0) {
      throw new Error("invalid token subject");
    }

    return {
      uid,
      username: typeof payload.username === "string" ? payload.username : null,
      sessionId: typeof payload.session_id === "string" ? payload.session_id : null,
      roles: Array.isArray(payload.roles) ? payload.roles.filter((role): role is string => typeof role === "string") : []
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
