import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyImportedYii3AccessToken } from "../src/identity-yii3-token-verifier.js";

const NOW = Date.parse("2026-10-12T00:00:00.000Z") / 1000;
const SECRET = "0123456789abcdef0123456789abcdef";
const ERROR = "Legacy Yii3 access token is not trusted";
const claims = { uid: 42, iat: NOW - 5.123456, exp: NOW - 5.123456 + 10800 };
let directory: string, configFile: string, secretFile: string;
let trust: Record<string, unknown>;

function sign(payload: unknown = claims, header: unknown = { alg: "HS256", typ: "JWT" }, key: string | Buffer = SECRET): string {
  const input = [header, payload].map((part) => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");
  return `${input}.${createHmac("sha256", key).update(input).digest("base64url")}`;
}
function configure(overrides: Record<string, unknown> = {}): void {
  writeFileSync(configFile, JSON.stringify({ ...trust, ...overrides }));
  vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", configFile);
}
function rejects(token: string): void {
  expect(() => verifyImportedYii3AccessToken(token)).toThrow(ERROR);
}

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "identity-yii3-trust-"));
  configFile = join(directory, "trust.json");
  secretFile = join(directory, "yii3.key");
  writeFileSync(secretFile, SECRET);
  trust = {
    version: 1, algorithm: "HS256", secretFile, maxAccessTtlSeconds: 10800,
    issuedBefore: new Date((NOW + 10) * 1000).toISOString(),
    acceptUntil: new Date((NOW + 300) * 1000).toISOString(),
  };
  vi.spyOn(Date, "now").mockReturnValue(NOW * 1000);
  vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  rmSync(directory, { recursive: true, force: true });
});

describe("independent bounded Yii3 HS256 access-token trust", () => {
  it("is off by default even when the older ES256 or OAuth trust is configured", () => {
    writeFileSync(configFile, JSON.stringify(trust));
    vi.stubEnv("IDENTITY_LEGACY_JWT_CONFIG_FILE", configFile);
    vi.stubEnv("IDENTITY_AUTH_LEGACY_JWT_CONFIG_FILE", configFile);
    rejects(sign());
    configure();
    expect(verifyImportedYii3AccessToken(sign())).toEqual(claims);
  });

  it("accepts ordinary and SN tokens with PHP's fractional dates and exact three-hour lifetime", () => {
    configure();
    expect(verifyImportedYii3AccessToken(sign())).toEqual(claims);
    const snClaims = { ...claims, auth_method: "device_sn", device_sn_id: 73 };
    expect(verifyImportedYii3AccessToken(sign(snClaims))).toEqual(snClaims);
    const integerClaims = { uid: 1, iat: NOW, exp: NOW + 10800 };
    expect(verifyImportedYii3AccessToken(sign(integerClaims, { alg: "HS256" }))).toEqual(integerClaims);
  });

  it("uses PHP trim bytes rather than JavaScript Unicode whitespace trimming", () => {
    configure();
    const bytes = Buffer.concat([Buffer.from(" \t\n\r\0\v"), Buffer.from(SECRET), Buffer.from("\v\0\r\n\t ")]);
    writeFileSync(secretFile, bytes);
    expect(verifyImportedYii3AccessToken(sign())).toEqual(claims);
    const nonPhpWhitespace = `\u00a0${SECRET}\u00a0`;
    writeFileSync(secretFile, nonPhpWhitespace);
    expect(verifyImportedYii3AccessToken(sign(claims, { alg: "HS256" }, nonPhpWhitespace))).toEqual(claims);
    rejects(sign());
  });

  it("does not cache a removed trust file or a replaced secret", () => {
    configure();
    expect(verifyImportedYii3AccessToken(sign())).toEqual(claims);
    const replacement = "fedcba9876543210fedcba9876543210";
    writeFileSync(secretFile, replacement);
    rejects(sign());
    expect(verifyImportedYii3AccessToken(sign(claims, { alg: "HS256" }, replacement))).toEqual(claims);
    rmSync(configFile);
    rejects(sign(claims, { alg: "HS256" }, replacement));
  });

  it.each([
    { alg: "none" }, { alg: "ES256" }, { alg: "HS384" }, { alg: "HS256", typ: "access" },
    { alg: "HS256", typ: null }, { alg: "HS256", kid: "legacy" },
    { alg: "HS256", crit: [] }, { alg: "HS256", jwk: {} }, { alg: "HS256", jku: "https://keys.test" },
  ])("rejects alternate algorithms and token-selected header trust: %j", (header) => {
    configure();
    rejects(sign(claims, header));
  });

  it.each([
    ["iss", "old-api"], ["aud", "business-api"], ["scope", "openid admin"], ["scp", ["admin"]],
    ["session_id", "native-session"], ["token_use", "access"], ["typ", "access"],
    ["sub", "42"], ["roles", ["root"]], ["permissions", ["*"]], ["nbf", NOW], ["jti", "id"],
  ])("rejects borrowed %s claims even with the trusted HMAC key", (key, value) => {
    configure();
    rejects(sign({ ...claims, [key as string]: value }));
  });

  it.each([0, -1, 1.5, "42", null, Number.MAX_SAFE_INTEGER + 1])("requires a positive safe integer uid: %j", (uid) => {
    configure();
    rejects(sign({ ...claims, uid }));
  });

  it.each([
    { auth_method: "device_sn" }, { device_sn_id: 73 }, { auth_method: "password", device_sn_id: 73 },
    { auth_method: null, device_sn_id: 73 }, { auth_method: "device_sn", device_sn_id: "73" },
    { auth_method: "device_sn", device_sn_id: 0 }, { auth_method: "device_sn", device_sn_id: -1 },
    { auth_method: "device_sn", device_sn_id: 1.5 }, { auth_method: "device_sn", device_sn_id: Number.MAX_SAFE_INTEGER + 1 },
  ])("rejects missing, forged or ambiguous SN provenance: %j", (source) => {
    configure();
    rejects(sign({ ...claims, ...source }));
  });

  it("enforces expiry, both trust deadlines, future skew and the maximum lifetime at their boundaries", () => {
    configure({ issuedBefore: "2026-10-12T08:00:10+08:00" });
    const future = { uid: 42, iat: NOW + 10, exp: NOW + 10 + 10800 };
    expect(verifyImportedYii3AccessToken(sign(future))).toEqual(future);
    rejects(sign({ ...future, iat: future.iat + 0.000001, exp: future.exp + 0.000001 }));
    rejects(sign({ ...claims, exp: claims.iat + 10800.000001 }));
    rejects(sign({ ...claims, exp: claims.iat }));
    rejects(sign({ uid: 42, iat: NOW - 60, exp: NOW }));
    configure({ issuedBefore: "2026-10-11T23:59:54.876544Z" });
    expect(verifyImportedYii3AccessToken(sign())).toEqual(claims);
    configure({ issuedBefore: "2026-10-11T23:59:54.876543Z" });
    rejects(sign());
    configure({ acceptUntil: new Date(NOW * 1000).toISOString(), issuedBefore: new Date((NOW - 1) * 1000).toISOString() });
    rejects(sign());
  });

  it("allows an operator to reduce, but never increase, the three-hour TTL ceiling", () => {
    configure({ maxAccessTtlSeconds: 60 });
    const short = { uid: 42, iat: NOW - 1, exp: NOW + 59 };
    expect(verifyImportedYii3AccessToken(sign(short))).toEqual(short);
    rejects(sign({ ...short, exp: short.exp + 0.000001 }));
    configure({ maxAccessTtlSeconds: 10801 });
    rejects(sign());
  });

  it.each([
    { iat: "1760227200" }, { exp: "1760227260" }, { iat: null }, { exp: null },
    { iat: 0 }, { iat: -1 }, { exp: -1 }, { iat: Number.MAX_SAFE_INTEGER + 1 },
  ])("rejects invalid numeric dates: %j", (time) => {
    configure();
    rejects(sign({ ...claims, ...time }));
  });

  it.each([
    { version: 2 }, { algorithm: "ES256" }, { secret: SECRET }, { secretFile: "" },
    { maxAccessTtlSeconds: 0 }, { maxAccessTtlSeconds: 1.5 }, { maxAccessTtlSeconds: "10800" },
    { issuedBefore: "next Tuesday" }, { acceptUntil: "2026-02-30T00:00:00Z" },
    { acceptUntil: "2026-10-12T24:00:00Z" },
    { issuedBefore: "2026-10-13T00:00:00Z", acceptUntil: "2026-10-12T01:00:00Z" },
  ])("fails closed for malformed or broader trust configuration: %j", (config) => {
    configure(config);
    rejects(sign());
  });

  it("rejects the other trust formats and malformed JSON without exposing file paths or secrets", () => {
    configure();
    for (const contents of ["null", "[]", JSON.stringify([trust]), "{", "x".repeat(16385)]) {
      writeFileSync(configFile, contents);
      rejects(sign());
    }
    configure({ secretFile: join(directory, "private-source-key-does-not-exist") });
    try { verifyImportedYii3AccessToken(sign()); } catch (error) {
      expect((error as Error).message).toBe(ERROR);
      expect((error as Error).message).not.toContain(directory);
      expect((error as Error).message).not.toContain(SECRET);
    }
  });

  it("bounds key files and rejects short trimmed keys and non-files", () => {
    configure();
    for (const bytes of [Buffer.alloc(0), Buffer.from(" \0\v" + "x".repeat(31) + "\n"), Buffer.alloc(16385, "x")]) {
      writeFileSync(secretFile, bytes);
      rejects(sign());
    }
    configure({ secretFile: directory });
    rejects(sign());
    vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", directory);
    rejects(sign());
  });

  it("requires the exact signature and canonical bounded compact JWT encoding", () => {
    configure();
    const valid = sign(), parts = valid.split(".");
    rejects(sign(claims, { alg: "HS256" }, "untrusted-signing-key-with-32-bytes"));
    rejects(`${parts[0]}.${parts[1]}.${Buffer.alloc(32).toString("base64url")}`);
    rejects(`${parts[0]}.${parts[1]}.${Buffer.alloc(31).toString("base64url")}`);
    rejects(`${valid}.extra`);
    rejects(`${parts[0]}=.${parts[1]}.${parts[2]}`);
    rejects(`${parts[0]}.${parts[1]}.`);
    rejects("x".repeat(8193));
    rejects(sign(null));
    rejects(sign([]));
    rejects(sign(claims, []));
    // Noncanonical unused base64 bits must not alias the same signed bytes.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = parts[2].at(-1)!;
    const alias = parts[2].slice(0, -1) + alphabet[alphabet.indexOf(last) + 1];
    rejects(`${parts[0]}.${parts[1]}.${alias}`);
  });
});
