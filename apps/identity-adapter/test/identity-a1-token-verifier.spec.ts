import { createHmac, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { verifyImportedA1AccessToken } from "../src/identity-a1-token-verifier.js";
import { verifyImportedYii3AccessToken } from "../src/identity-yii3-token-verifier.js";
import { verifyImportedAccessToken } from "../src/legacy-token-verifier.js";
import { JwtIssuerService } from "../src/jwt-issuer.service.js";

const NOW = Date.parse("2026-10-12T00:00:00.000Z") / 1000;
const SECRET = Buffer.from(" \tsynthetic-a1-fixture-key-0123456789abcdef\r\n");
const claims = { iss: "https://a1.example.test", uid: 42, iat: NOW - 1.123456, nbf: NOW - 1.123456, exp: NOW - 1.123456 + 10800 };
const ERROR = "Legacy A1 access token is not trusted";
let directory: string, configFile: string, secretFile: string, trust: Record<string, unknown>;
function sign(payload: unknown = claims, header: unknown = { alg: "HS256", typ: "JWT" }, key = SECRET) {
  const input = [header, payload].map(part => Buffer.from(JSON.stringify(part)).toString("base64url")).join(".");
  return `${input}.${createHmac("sha256", key).update(input).digest("base64url")}`;
}
function configure(overrides: Record<string, unknown> = {}) {
  writeFileSync(configFile, JSON.stringify({ ...trust, ...overrides }));
  vi.stubEnv("IDENTITY_LEGACY_A1_JWT_CONFIG_FILE", configFile);
}
const rejects = (token: string) => expect(() => verifyImportedA1AccessToken(token)).toThrow(ERROR);
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "identity-a1-trust-"));
  configFile = join(directory, "trust.json"); secretFile = join(directory, "synthetic-key");
  writeFileSync(secretFile, SECRET);
  trust = { version: 1, algorithm: "HS256", secretFile, issuers: [claims.iss], maxAccessTtlSeconds: 10800,
    issuedBefore: new Date((NOW + 10) * 1000).toISOString(), acceptUntil: new Date((NOW + 300) * 1000).toISOString() };
  vi.spyOn(Date, "now").mockReturnValue(NOW * 1000);
  for (const variable of ["IDENTITY_LEGACY_A1_JWT_CONFIG_FILE", "IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", "IDENTITY_LEGACY_JWT_CONFIG_FILE"])
    vi.stubEnv(variable, "");
});
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); rmSync(directory, { recursive: true, force: true }); });

describe("separate bounded A1 HS256 trust", () => {
  it("is disabled until its own reviewed profile is mounted", () => {
    writeFileSync(configFile, JSON.stringify(trust));
    vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", configFile);
    vi.stubEnv("IDENTITY_LEGACY_JWT_CONFIG_FILE", configFile);
    rejects(sign()); configure(); expect(verifyImportedA1AccessToken(sign())).toEqual(claims);
  });
  it("verifies the real Bizley/Lcobucci PHP fixture including raw key whitespace and microsecond dates", () => {
    const fixture = JSON.parse(readFileSync(new URL("fixtures/a1-legacy-access-token.json", import.meta.url), "utf8"));
    expect(fixture).toMatchObject({ syntheticOnly: true, sourceRevision: "f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74", bizleyVersion: "4.1.2" });
    expect(Buffer.from(fixture.secretBase64, "base64")).toEqual(SECRET);
    configure();
    expect(verifyImportedAccessToken(fixture.token)).toEqual({ iss: claims.iss, uid: 42, iat: NOW + 0.123456, nbf: NOW + 0.123456, exp: NOW + 10800.123456 });
    expect(verifyImportedAccessToken(fixture.stringUidToken)).toMatchObject({ uid: "42", iss: claims.iss });
    writeFileSync(secretFile, SECRET.toString().trim()); rejects(fixture.token);
    writeFileSync(secretFile, SECRET.toString("base64")); rejects(fixture.token);
  });
  it("re-reads replaced keys and removed trust on every verification", () => {
    configure(); expect(verifyImportedA1AccessToken(sign())).toEqual(claims);
    const replacement = Buffer.from("replacement-synthetic-a1-key-with-32-bytes");
    writeFileSync(secretFile, replacement); rejects(sign());
    expect(verifyImportedA1AccessToken(sign(claims, undefined, replacement))).toEqual(claims);
    rmSync(configFile); rejects(sign(claims, undefined, replacement));
  });
  it.each(["https://other.example.test", "http://a1.example.test", "https://A1.example.test", "https://a1.example.test/", "https://a1.example.test:443", null, [claims.iss]])("requires an exact reviewed issuer: %j", iss => {
    configure(); rejects(sign({ ...claims, iss }));
  });
  it.each(["aud", "sub", "session_id", "sid", "scope", "scp", "roles", "token_use", "auth_method", "device_sn_id", "jti", "typ"])("rejects extra %s authority or purpose claims", claim => {
    configure(); rejects(sign({ ...claims, [claim]: "borrowed" }));
  });
  it.each(["iss", "uid", "iat", "nbf", "exp"])("requires source claim %s", claim => {
    configure(); const payload: Record<string, unknown> = { ...claims }; delete payload[claim]; rejects(sign(payload));
  });
  it.each([{ alg: "none", typ: "JWT" }, { alg: "ES256", typ: "JWT" }, { alg: "HS384", typ: "JWT" }, { alg: "HS256" }, { alg: "HS256", typ: "access" }, { alg: "HS256", typ: "JWT", kid: "chosen-key" }, { alg: "HS256", typ: "JWT", crit: [] }])("rejects alternate algorithms or headers: %j", header => {
    configure(); rejects(sign(claims, header));
  });
  it.each([0, -1, 1.5, "0", "042", "+42", "42.0", "4.2e1", "42\n", "9007199254740992", null, Number.MAX_SAFE_INTEGER + 1])("requires a positive canonical safe uid: %j", uid => { configure(); rejects(sign({ ...claims, uid })); });
  it("enforces source nbf, issue deadline, exact expiry and the three-hour ceiling without expiry grace", () => {
    configure();
    const future = { ...claims, iat: NOW + 10, nbf: NOW + 10, exp: NOW + 10810 };
    expect(verifyImportedA1AccessToken(sign(future))).toEqual(future);
    rejects(sign({ ...future, iat: NOW + 10.001, nbf: NOW + 10.001, exp: NOW + 10810.001 }));
    rejects(sign({ ...claims, nbf: claims.iat - 0.001 })); rejects(sign({ ...claims, nbf: claims.iat + 0.001 }));
    rejects(sign({ ...claims, exp: claims.iat + 10800.001 })); rejects(sign({ ...claims, exp: NOW }));
    configure({ issuedBefore: new Date((claims.iat - 0.001) * 1000).toISOString() }); rejects(sign());
    configure({ acceptUntil: new Date(NOW * 1000).toISOString(), issuedBefore: new Date((NOW - 1) * 1000).toISOString() }); rejects(sign());
    configure({ maxAccessTtlSeconds: 60 }); rejects(sign());
    const short = { ...claims, exp: claims.iat + 60 }; expect(verifyImportedA1AccessToken(sign(short))).toEqual(short);
  });
  it.each([{ iat: null }, { nbf: "1" }, { exp: null }, { iat: 0, nbf: 0 }, { exp: -1 }, { iat: Number.MAX_SAFE_INTEGER + 1, nbf: Number.MAX_SAFE_INTEGER + 1 }])("rejects invalid numeric dates: %j", time => { configure(); rejects(sign({ ...claims, ...time })); });
  it.each([{ version: 2 }, { algorithm: "ES256" }, { secret: "inline-not-allowed" }, { secretFile: "" }, { maxAccessTtlSeconds: 10801 }, { maxAccessTtlSeconds: "10800" }, { issuers: [] }, { issuers: [claims.iss, claims.iss] }, { issuers: ["*"] }, { issuers: ["https://user@a1.example.test"] }, { issuedBefore: "tomorrow" }, { acceptUntil: "2026-02-30T00:00:00Z" }, { acceptUntil: "2026-10-12T24:00:00Z" }, { issuedBefore: "2026-10-14T00:00:00Z" }])("rejects malformed or broader trust: %j", config => { configure(config); rejects(sign()); });
  it("bounds keys and files, and reports no mounted path or token details", () => {
    configure();
    for (const bytes of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(16385)]) { writeFileSync(secretFile, bytes); rejects(sign()); }
    configure({ secretFile: directory }); rejects(sign());
    configure({ secretFile: join(directory, "missing") }); rejects(sign());
    for (const text of ["null", "[]", "{", "x".repeat(16385)]) { writeFileSync(configFile, text); rejects(sign()); }
    vi.stubEnv("IDENTITY_LEGACY_A1_JWT_CONFIG_FILE", directory); rejects(sign());
  });
  it("requires a canonical bounded JWT and an exact valid signature", () => {
    configure(); const valid = sign(), parts = valid.split(".");
    rejects(sign(claims, undefined, Buffer.alloc(32))); rejects(`${valid}.extra`);
    rejects(`${parts[0]}=.${parts[1]}.${parts[2]}`); rejects(`${parts[0]}.${parts[1]}.${Buffer.alloc(31).toString("base64url")}`);
    rejects(`${valid}\n`); rejects("x".repeat(8193)); rejects(sign(null)); rejects(sign([]));
  });
  it("never falls back between the A1, Yii3 and ES256/OAuth profiles", () => {
    configure();
    const yii3File = join(directory, "yii3-trust.json");
    writeFileSync(yii3File, JSON.stringify({ ...trust, issuers: undefined }));
    vi.stubEnv("IDENTITY_LEGACY_YII3_JWT_CONFIG_FILE", yii3File);
    expect(() => verifyImportedYii3AccessToken(sign())).toThrow();
    const yii3Claims = { uid: 42, iat: claims.iat, exp: claims.exp };
    const yii3Token = sign(yii3Claims, undefined, Buffer.from(SECRET.toString().trim()));
    expect(verifyImportedAccessToken(yii3Token)).toEqual(yii3Claims);
    rejects(yii3Token);
    // A1 with a valid Yii3 signature still fails A1 verification, without a key fallback.
    expect(() => verifyImportedAccessToken(sign(claims, undefined, Buffer.from(SECRET.toString().trim())))).toThrow(ERROR);
    vi.stubEnv("IDENTITY_DATA_SOURCE", "identity");
    const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    vi.stubEnv("IDENTITY_JWT_PUBLIC_KEY_PEM", keys.publicKey.export({ format: "pem", type: "spki" }).toString());
    const jwt = new JwtIssuerService();
    expect(jwt.verifyAccessToken(sign())).toMatchObject({ uid: 42, sessionId: null, roles: [], importedLegacy: true });
    expect(() => jwt.verifyAccessToken(sign(), { audience: "oidc-client" })).toThrow();
  });
});
