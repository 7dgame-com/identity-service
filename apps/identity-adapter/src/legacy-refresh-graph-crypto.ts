import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { graphBodySchema, graphHash, graphTokens, type GraphBody, type GraphReplay, type GraphProtocol } from "./legacy-refresh-graph-manifest.js";
import { verifyImportedAccessToken } from "./legacy-token-verifier.js";

export function graphEncryptionKey(value = process.env.IDENTITY_REFRESH_REPLAY_KEY): Buffer {
  if (!value) throw new Error("Legacy graph replay encryption is unavailable.");
  const key = Buffer.from(value, "base64url");
  if (key.length !== 32 || (key.toString("base64url") !== value && key.toString("base64") !== value)) throw new Error("Legacy graph replay encryption is unavailable.");
  return key;
}
export function encryptGraphBody(body: GraphBody, key: Buffer, aad: string): string {
  if (key.length !== 32) throw new Error("Legacy graph replay encryption is unavailable.");
  const plain = Buffer.from(JSON.stringify(body)); if (plain.length > 262144) throw new Error("Legacy graph response exceeds the bound.");
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv); cipher.setAAD(Buffer.from(aad));
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
}
export function decryptGraphBody(value: string, key: Buffer, aad: string): GraphBody {
  try {
    if (key.length !== 32 || value.length > 400000) throw new Error();
    const raw = Buffer.from(value, "base64url"); if (raw.length < 29 || raw.toString("base64url") !== value) throw new Error();
    const cipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12)); cipher.setAAD(Buffer.from(aad)); cipher.setAuthTag(raw.subarray(12, 28));
    return graphBodySchema.parse(JSON.parse(Buffer.concat([cipher.update(raw.subarray(28)), cipher.final()]).toString("utf8")));
  } catch { throw new Error("Legacy graph replay cannot be authenticated."); }
}
export function graphBodyAad(protocol: GraphProtocol, replay: Omit<GraphReplay, "response">): string {
  return JSON.stringify(["identity-legacy-full-response-v1", protocol, replay.consumer, replay.endpoint, replay.issuer,
    replay.predecessorHash, replay.successorHash, replay.userId, replay.familyId, replay.accountEpoch, replay.accountFingerprint,
    replay.userEpoch, replay.requestHash, replay.createdAtMs, replay.expiresAtMs]);
}
/** Source AES authentication precedes graph normalization; no key enters its manifest. */
export function decryptSourceGraphResponse(protocol: GraphProtocol, replay: Omit<GraphReplay, "response">, value: string, key: Buffer): GraphBody {
  const aad = protocol === "yii3" ? JSON.stringify(["y1-refresh-response-v1", replay.predecessorHash, replay.successorHash,
    replay.userId, replay.familyId, Number(replay.userEpoch), replay.accountFingerprint, replay.accountEpoch]) : JSON.stringify([
    "legacy-ar-refresh-response-v1", replay.consumer, replay.endpoint, replay.issuer, replay.predecessorHash, replay.successorHash,
    String(replay.userId), replay.familyId, replay.userEpoch, replay.accountEpoch, replay.accountFingerprint,
    replay.requestHash ?? "none", String(replay.createdAtMs), String(replay.expiresAtMs)]);
  // AR's canonical encoding is padded standard base64; Y1 uses base64url.
  let encoded = value;
  if (protocol === "ar") {
    const raw = Buffer.from(value, "base64"); if (raw.toString("base64") !== value) throw new Error("Invalid source replay encoding.");
    encoded = raw.toString("base64url");
  }
  return decryptGraphBody(encoded, key, aad);
}
/** Verify the actual source signer before an old JWT may be returned unchanged. */
export function verifyGraphResponse(replay: GraphReplay, verify = verifyImportedAccessToken, atMs = Date.now()): Record<string, unknown> {
  const tokens = graphTokens(replay.response), claims = verify(tokens.accessToken, atMs);
  const header = JSON.parse(Buffer.from(tokens.accessToken.split(".")[0], "base64url").toString("utf8"));
  const uid = Number(claims.uid);
  if (!Number.isSafeInteger(uid) || uid !== replay.userId || graphHash(tokens.refreshToken) !== replay.successorHash
    || header.alg !== (replay.consumer === "server" ? "ES256" : "HS256")
    || (replay.consumer === "yii3" ? claims.iss !== undefined || claims.aud !== undefined : claims.iss !== replay.issuer)
    || (replay.consumer === "a1" && claims.aud !== undefined)
    || typeof claims.exp !== "number" || typeof claims.iat !== "number" || claims.exp <= claims.iat || claims.exp - claims.iat > 10800
    || claims.iat * 1000 > replay.createdAtMs + 10_000 || claims.exp * 1000 < replay.expiresAtMs) {
    throw new Error("Legacy graph response signer or scope is invalid.");
  }
  return claims;
}
