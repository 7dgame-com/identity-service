import { createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { TextDecoder } from "node:util";

const MAX_FILE_BYTES = 16 * 1024;
const MAX_TOKEN_BYTES = 8 * 1024;
const MAX_ACCESS_TTL_SECONDS = 10800;
const REJECTION = "Legacy Yii3 access token is not trusted";
const decoder = new TextDecoder("utf-8", { fatal: true });
const trustKeys = new Set(["version", "algorithm", "secretFile", "issuedBefore", "acceptUntil", "maxAccessTtlSeconds"]);
const headerKeys = new Set(["alg", "typ"]);
const claimKeys = new Set(["uid", "iat", "exp", "auth_method", "device_sn_id"]);

function reject(): never { throw new Error(REJECTION); }

function readBoundedFile(path: string): Buffer {
  // Nonblocking open also prevents a misconfigured FIFO from stalling authentication.
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

function positiveId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function numericDate(value: unknown): value is number {
  // Lcobucci's default formatter emits fractional seconds when the PHP clock has microseconds.
  return typeof value === "number" && Number.isFinite(value) && value > 0 && value <= Number.MAX_SAFE_INTEGER;
}

function phpTrim(bytes: Buffer): Buffer {
  const trimmed = (byte: number) => byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d || byte === 0x00 || byte === 0x0b;
  let start = 0, end = bytes.length;
  while (start < end && trimmed(bytes[start])) start++;
  while (end > start && trimmed(bytes[end - 1])) end--;
  return bytes.subarray(start, end);
}

/**
 * Opt-in, time-bounded verification of JwtService.php's original HS256 access tokens.
 * The caller must still check live private-account status, roles, revocation cutoff and SN provenance.
 */
export function verifyImportedYii3AccessToken(token: string, atMs = Date.now()): Record<string, unknown> {
  try {
    const configFile = process.env.IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE;
    if (!configFile || typeof token !== "string" || token.length > MAX_TOKEN_BYTES) reject();
    // Read on every attempt: removing trust or replacing the mounted key takes effect immediately.
    const trust = object(JSON.parse(decoder.decode(readBoundedFile(configFile))), trustKeys);
    if (trust.version !== 1 || trust.algorithm !== "HS256" || typeof trust.secretFile !== "string"
      || trust.secretFile.length === 0 || trust.secretFile.length > 4096 || trust.secretFile.includes("\0")
      || !positiveId(trust.maxAccessTtlSeconds) || trust.maxAccessTtlSeconds > MAX_ACCESS_TTL_SECONDS) reject();
    const issuedBefore = isoSeconds(trust.issuedBefore), acceptUntil = isoSeconds(trust.acceptUntil);
    if (!Number.isSafeInteger(atMs) || atMs <= 0) reject();
    const now = atMs / 1000;
    if (issuedBefore > acceptUntil || now >= acceptUntil) reject();

    const parts = token.split(".");
    if (parts.length !== 3) reject();
    const header = object(JSON.parse(decoder.decode(decodePart(parts[0]))), headerKeys);
    if (header.alg !== "HS256" || (Object.hasOwn(header, "typ") && header.typ !== "JWT")) reject();
    const claims = object(JSON.parse(decoder.decode(decodePart(parts[1]))), claimKeys);
    if (!positiveId(claims.uid) || !numericDate(claims.iat) || !numericDate(claims.exp)
      || claims.exp <= now || claims.iat > now + 10 || claims.iat > issuedBefore
      || claims.exp <= claims.iat || claims.exp - claims.iat > trust.maxAccessTtlSeconds) reject();
    const hasMethod = Object.hasOwn(claims, "auth_method"), hasSn = Object.hasOwn(claims, "device_sn_id");
    if (hasMethod !== hasSn || (hasMethod && (claims.auth_method !== "device_sn" || !positiveId(claims.device_sn_id)))) reject();

    const secret = phpTrim(readBoundedFile(trust.secretFile));
    if (secret.length < 32) reject();
    const signature = decodePart(parts[2]);
    if (signature.length !== 32) reject();
    const expected = createHmac("sha256", secret).update(`${parts[0]}.${parts[1]}`).digest();
    if (!timingSafeEqual(expected, signature)) reject();
    return claims;
  } catch {
    // Never expose a token, secret, mounted path or underlying filesystem error to callers.
    return reject();
  }
}
