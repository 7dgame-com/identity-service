import { createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { TextDecoder } from "node:util";

const MAX_FILE_BYTES = 16 * 1024;
const MAX_TOKEN_BYTES = 8 * 1024;
const REJECTION = "Legacy A1 access token is not trusted";
const decoder = new TextDecoder("utf-8", { fatal: true });
const trustKeys = new Set(["version", "algorithm", "secretFile", "issuers", "issuedBefore", "acceptUntil", "maxAccessTtlSeconds"]);
const headerKeys = new Set(["alg", "typ"]);
const claimKeys = new Set(["iss", "uid", "iat", "nbf", "exp"]);

function reject(): never { throw new Error(REJECTION); }

function readBoundedFile(path: string): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) reject();
    const bytes = Buffer.alloc(MAX_FILE_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
    }
    if (length > MAX_FILE_BYTES) reject();
    return bytes.subarray(0, length);
  } finally { closeSync(descriptor); }
}

function object(value: unknown, keys: ReadonlySet<string>): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) reject();
  if (!Object.keys(value).every((key) => keys.has(key))) reject();
  return value as Record<string, unknown>;
}

function decodePart(part: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) reject();
  const bytes = Buffer.from(part, "base64url");
  if (bytes.toString("base64url") !== part) reject();
  return bytes;
}

function positiveId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function subjectId(value: unknown): boolean {
  // Yii passes its DB attribute directly to withClaim, without an integer cast.
  return positiveId(value) || (typeof value === "string" && /^[1-9][0-9]*$/.test(value)
    && value === String(Number(value)) && positiveId(Number(value)));
}

function numericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 && value <= Number.MAX_SAFE_INTEGER;
}

function isoSeconds(value: unknown): number {
  if (typeof value !== "string") reject();
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match || match[0] !== value) reject();
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, zone] = match;
  const year = Number(yearText), month = Number(monthText), day = Number(dayText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]
    || Number(hourText) > 23 || Number(minuteText) > 59 || Number(secondText) > 59) reject();
  const seconds = Date.parse(`${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondText}${zone}`) / 1000
    + (fraction ? Number(`0.${fraction}`) : 0);
  if (!Number.isFinite(seconds) || seconds <= 0) reject();
  return seconds;
}

function issuer(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const url = new URL(value);
    // Yii request.hostInfo has a scheme, authority and optional non-default port only.
    return (url.protocol === "http:" || url.protocol === "https:") && url.origin === value;
  } catch { return false; }
}

/**
 * Separate opt-in trust for A1 User::generateAccessToken's original HS256 profile.
 * METHOD_FILE / Lcobucci InMemory::file uses all key bytes, without PHP trim or base64 decoding.
 * Live private-account status, roles and revocation cutoffs remain the caller's responsibility.
 */
export function verifyImportedA1AccessToken(token: string): Record<string, unknown> {
  try {
    const configFile = process.env.IDENTITY_LEGACY_A1_JWT_CONFIG_FILE;
    if (!configFile || typeof token !== "string" || token.length > MAX_TOKEN_BYTES) reject();
    const trust = object(JSON.parse(decoder.decode(readBoundedFile(configFile))), trustKeys);
    if (trust.version !== 1 || trust.algorithm !== "HS256" || typeof trust.secretFile !== "string"
      || !trust.secretFile.length || trust.secretFile.length > 4096 || trust.secretFile.includes("\0")
      || !positiveId(trust.maxAccessTtlSeconds) || trust.maxAccessTtlSeconds > 10800
      || !Array.isArray(trust.issuers) || trust.issuers.length < 1 || trust.issuers.length > 20
      || !trust.issuers.every(issuer) || new Set(trust.issuers).size !== trust.issuers.length) reject();
    const issuedBefore = isoSeconds(trust.issuedBefore), acceptUntil = isoSeconds(trust.acceptUntil);
    const now = Date.now() / 1000;
    if (issuedBefore > acceptUntil || now >= acceptUntil) reject();

    const parts = token.split(".");
    if (parts.length !== 3) reject();
    const header = object(JSON.parse(decoder.decode(decodePart(parts[0]))), headerKeys);
    if (header.alg !== "HS256" || header.typ !== "JWT") reject();
    const claims = object(JSON.parse(decoder.decode(decodePart(parts[1]))), claimKeys);
    if (!issuer(claims.iss) || !trust.issuers.includes(claims.iss) || !subjectId(claims.uid)
      || !numericDate(claims.iat) || !numericDate(claims.nbf) || !numericDate(claims.exp)
      || claims.nbf !== claims.iat || claims.iat > now + 10 || claims.iat > issuedBefore
      || claims.exp <= now || claims.exp <= claims.iat || claims.exp - claims.iat > trust.maxAccessTtlSeconds) reject();

    const secret = readBoundedFile(trust.secretFile);
    if (secret.length < 32) reject();
    const signature = decodePart(parts[2]);
    if (signature.length !== 32) reject();
    const expected = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest();
    if (!timingSafeEqual(expected, signature)) reject();
    return claims;
  } catch {
    return reject();
  }
}
