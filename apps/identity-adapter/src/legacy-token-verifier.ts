import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { verifyImportedYii3AccessToken } from "./identity-yii3-token-verifier.js";
import { verifyImportedA1AccessToken } from "./identity-a1-token-verifier.js";

/** Explicit, time-bounded trust for credentials issued before the cutover. */
export function verifyImportedAccessToken(token: string, atMs = Date.now()): Record<string, unknown> {
  // Each historical signer has independent trust. The unverified shape only
  // selects one strict verifier; failure never falls through to another key.
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid token format");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header?.alg === "HS256") {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return claims && typeof claims === "object" && Object.hasOwn(claims, "iss")
      ? verifyImportedA1AccessToken(token, atMs) : verifyImportedYii3AccessToken(token, atMs);
  }
  const filename = process.env.IDENTITY_LEGACY_JWT_CONFIG_FILE;
  if (!filename) throw new Error("legacy token trust is not configured");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const entries: unknown = JSON.parse(readFileSync(filename, "utf8"));
  if (!Array.isArray(entries)) throw new Error("invalid legacy token trust configuration");
  if (header.alg !== "ES256" || !payload || typeof payload !== "object") throw new Error("invalid legacy token algorithm");
  if (!Number.isSafeInteger(atMs) || atMs <= 0) throw new Error("invalid legacy verification time");
  const now = atMs / 1000;
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp) || payload.exp <= now || typeof payload.iat !== "number" || !Number.isFinite(payload.iat)
      || payload.iat > now + 10 || (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > now + 10))) {
    throw new Error("legacy token time invalid");
  }
  for (const entry of entries) {
    if (!entry || entry.algorithm !== "ES256" || typeof entry.publicKeyFile !== "string") continue;
    const deadline = Date.parse(entry.acceptUntil) / 1000;
    const lastIssue = Date.parse(entry.issuedBefore) / 1000;
    if (!Number.isFinite(deadline) || !Number.isFinite(lastIssue) || now >= deadline || payload.iat > lastIssue) continue;
    if ((payload.iss ?? null) !== (entry.issuer ?? null) || !sameAudience(payload.aud, entry.audience)) continue;
    if (entry.kid !== undefined && entry.kid !== header.kid) continue;
    const publicKey = createPublicKey(readFileSync(entry.publicKeyFile, "utf8"));
    if (verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(parts[2], "base64url"))) return payload;
  }
  throw new Error("legacy token is not trusted");
}

function sameAudience(actual: unknown, expected: unknown): boolean {
  const values = (value: unknown) => value == null ? [] : Array.isArray(value) ? value : [value];
  const a=values(actual), b=values(expected);
  return a.length===b.length && a.every((value,index)=>typeof value === "string" && value===b[index]);
}
