import { createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";
import type { LegacyUserReadModel } from "./legacy-identity.reader.js";

export interface IssuedAccessToken {
  accessToken: string;
  expiresAt: Date;
  jwtId: string;
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
