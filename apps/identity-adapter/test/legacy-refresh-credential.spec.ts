import "reflect-metadata";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { exportLegacyRefreshCredentials, legacyRefreshAccountFingerprint, normalizeLegacyRefreshCredentialManifest } from "../src/legacy-refresh-credential-manifest.js";
import { legacyRefreshCredentialSchema } from "../src/legacy-refresh-credential-schema.js";
import { AuthController } from "../src/auth.controller.js";
import { Yii3CompatibilityService } from "../src/yii3-compatibility.service.js";
import type { TokenIssuanceService } from "../src/token-issuance.service.js";
import type { NativeQrcodeService } from "../src/native-qrcode.service.js";
import type { NativeIdentityService } from "../src/native-identity.service.js";
import type { NativeQrcodeRepository } from "../src/native-qrcode.repository.js";
import type { IdentitySessionRepository } from "../src/identity-session.repository.js";
import type { LegacyRefreshCredentialRepository } from "../src/legacy-refresh-credential.repository.js";

const source = { storage: "yii2-redis-active-record-hash", redisDatabase: 1, keyPrefix: "refresh_token:a:",
  a1Revision: "f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74", serverRevision: "1".repeat(40), namespaceReviewed: true,
  keyEncodingReviewed: true, accountSnapshotReviewed: true, writersDrained: true, a1LookupReviewed: true, serverLookupReviewed: true };
const token = "a".repeat(32), fingerprint = legacyRefreshAccountFingerprint("source-password-hash", "source-auth-key");
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
function snapshot() { return { version: 1, source: { ...source }, capturedAt: "2026-10-12T00:00:00.000Z",
  accounts: [{ userId: 42, accountFingerprint: fingerprint }], entries: [{ redisKey: "refresh_token:a:7", type: "hash", pttl: -1,
    sourceKind: "a1", keyEncoding: "plain", a1Compatible: true, serverCompatible: true, fields: { id: "7", user_id: "42", key: token } }] } as any; }

describe("reviewed hash-only Yii AR legacy credentials", () => {
  it("preserves a genuine no-expiry A1 credential without inventing issuance or a 30-day lifetime", () => {
    const { manifest, report } = exportLegacyRefreshCredentials(snapshot());
    expect(manifest.credentials[0]).toMatchObject({ credentialHash: hash(token), expiresAt: null, sourceRevokedAt: null, a1Compatible: true });
    expect(manifest.credentials[0]).not.toHaveProperty("issuedAt"); expect(manifest.credentials[0]).not.toHaveProperty("createdAt");
    expect(JSON.stringify(manifest)).not.toContain(token); expect(JSON.stringify(manifest)).not.toContain("source-password-hash");
    expect(JSON.stringify(manifest)).not.toContain("source-auth-key");
    expect(report).toEqual({ total: 1, permanent: 1, expiring: 0, sourceRevoked: 0, notFinal: true, sourceWrites: 0, targetWrites: 0 });
    expect(JSON.stringify(report)).not.toMatch(/42|credentialHash|userId|refresh_token|key|source-password/);
  });
  it("keeps an expanded server record's original expiry and revocation while A1 metadata stays separate", () => {
    const input = snapshot(), entry = input.entries[0]; entry.sourceKind = "server";
    Object.assign(entry.fields, { session_id: "historical-session", created_at: "1700000000", expires_at: "1700604800", revoked_at: "1700100000" });
    const row = exportLegacyRefreshCredentials(input).manifest.credentials[0];
    expect(row.expiresAt).toBe(new Date(1700604800_000).toISOString());
    expect(row.sourceRevokedAt).toBe(new Date(1700100000_000).toISOString()); expect(row.a1Compatible).toBe(true);
    const manifest = exportLegacyRefreshCredentials(input).manifest; manifest.credentials[0].expiresAt = null;
    expect(() => normalizeLegacyRefreshCredentialManifest(manifest)).toThrow("lifetime evidence");
  });
  it("uses explicit encoding even when both plaintext and a stored hash have the same 64-hex shape", () => {
    const plain = snapshot(); plain.entries[0].sourceKind = "server"; plain.entries[0].fields.key = "b".repeat(64);
    const stored = structuredClone(plain); stored.entries[0].keyEncoding = "sha256-hex"; stored.entries[0].a1Compatible = false;
    expect(exportLegacyRefreshCredentials(plain).manifest.credentials[0].credentialHash).toBe(hash("b".repeat(64)));
    expect(exportLegacyRefreshCredentials(stored).manifest.credentials[0].credentialHash).toBe("b".repeat(64));
  });
  it.each(["storage", "redisDatabase", "keyPrefix", "namespaceReviewed", "keyEncodingReviewed", "accountSnapshotReviewed", "writersDrained"])(
    "requires reviewed source proof %s", field => {
      const input = snapshot(); delete input.source[field]; expect(() => exportLegacyRefreshCredentials(input)).toThrow();
    });
  it.each(["\n", "\r", "\r\n", "\u2028", "\u2029"])("rejects malformed trailing data %j", suffix => {
    for (const mutate of [(input: any) => input.source.a1Revision += suffix, (input: any) => input.entries[0].fields.key += suffix,
      (input: any) => input.entries[0].fields.user_id += suffix, (input: any) => input.entries[0].redisKey += suffix,
      (input: any) => input.capturedAt += suffix, (input: any) => input.accounts[0].accountFingerprint += suffix]) {
      const input = snapshot(); mutate(input); expect(() => exportLegacyRefreshCredentials(input)).toThrow();
    }
    for (const length of [32, 64]) {
      const input = snapshot(); if (length === 64) input.entries[0].sourceKind = "server";
      input.entries[0].fields.key = "a".repeat(length - suffix.length) + suffix;
      expect(() => exportLegacyRefreshCredentials(input)).toThrow();
    }
  });
  it.each([0, -2, 1, 2592000_000])("rejects unreviewed Redis TTL %s", pttl => {
    const input = snapshot(); input.entries[0].pttl = pttl; expect(() => exportLegacyRefreshCredentials(input)).toThrow();
  });
  it("rejects y1 strings, foreign namespaces, unknown fields, ambiguous IDs and missing account proof", () => {
    for (const mutate of [(input: any) => input.entries[0].type = "string", (input: any) => input.entries[0].redisKey = "refresh_token:raw",
      (input: any) => input.entries[0].fields.user_id = "042", (input: any) => input.entries[0].fields.id = "9007199254740992",
      (input: any) => input.entries[0].fields.scope = "admin", (input: any) => input.accounts = [],
      (input: any) => input.accounts.push(input.accounts[0]), (input: any) => input.entries.push(input.entries[0])]) {
      const input = snapshot(); mutate(input); expect(() => exportLegacyRefreshCredentials(input)).toThrow();
    }
  });
  it("never infers A1 compatibility from shape or silently drops device provenance", () => {
    for (const mutate of [(input: any) => input.source.a1LookupReviewed = false,
      (input: any) => { input.entries[0].sourceKind = "server"; input.entries[0].keyEncoding = "sha256-hex"; input.entries[0].fields.key = "a".repeat(64); },
      (input: any) => { input.entries[0].sourceKind = "server"; input.entries[0].fields.auth_method = "device_sn"; input.entries[0].fields.device_sn_id = "9"; }]) {
      const input = snapshot(); mutate(input); expect(() => exportLegacyRefreshCredentials(input)).toThrow();
    }
    const noException = snapshot(); noException.entries[0].a1Compatible = false; noException.source.a1LookupReviewed = false;
    expect(exportLegacyRefreshCredentials(noException).manifest.credentials[0].a1Compatible).toBe(false);
    const noServerProof = snapshot(); noServerProof.source.serverLookupReviewed = false;
    expect(() => exportLegacyRefreshCredentials(noServerProof)).toThrow("Server compatibility");
    const emptyProvenance = snapshot(); emptyProvenance.entries[0].sourceKind = "server"; emptyProvenance.entries[0].fields.auth_method = "";
    expect(() => exportLegacyRefreshCredentials(emptyProvenance)).toThrow("provenance-aware");
    const directManifest = exportLegacyRefreshCredentials(snapshot()).manifest;
    directManifest.credentials[0].sourceKind = "server"; directManifest.credentials[0].sourceFields.push("auth_method");
    expect(() => normalizeLegacyRefreshCredentialManifest(directManifest)).toThrow("source field evidence");
  });
  it("distinguishes all source account credential changes including null and empty values", () => {
    expect(new Set([[null, null], ["", null], [null, ""], ["old", "key"], ["new", "key"], ["old", "new"]]
      .map(([password, key]) => legacyRefreshAccountFingerprint(password, key))).size).toBe(6);
  });
  it("ships identical standalone, runtime and automatic schema assets", () => {
    const standalone = readFileSync(new URL("../../../deploy/mysql/identity-legacy-refresh-credential-schema.sql", import.meta.url), "utf8");
    expect(standalone.split("\n").filter(line => !line.startsWith("--")).join("\n").trim()).toBe(legacyRefreshCredentialSchema);
    expect(readFileSync(new URL("../../../deploy/mysql/identity-runtime-schema.sql", import.meta.url), "utf8")).toContain(legacyRefreshCredentialSchema);
  });
});

describe("legacy credential routing stays scoped", () => {
  it("classifies raw and wrapped revoked legacy credentials before login-code fallback", async () => {
    const native = { enabled: true, verify: vi.fn() }, codes = { redeemLoginCode: vi.fn() }, repository = { loginCode: vi.fn() };
    const sessions = { hasRefreshToken: vi.fn(async () => false) }, ledger = { hasCredential: vi.fn(async (raw: string) => raw === token) };
    const tokens = { refresh: vi.fn(async () => { throw new Error("revoked legacy credential"); }) };
    const service = new Yii3CompatibilityService(native as unknown as NativeIdentityService, repository as unknown as NativeQrcodeRepository,
      codes as unknown as NativeQrcodeService, sessions as unknown as IdentitySessionRepository, tokens as unknown as TokenIssuanceService,
      ledger as unknown as LegacyRefreshCredentialRepository);
    for (const raw of [token, `web_${token}`, `https://frontend.test?web_${token}`]) {
      await expect(service.refresh({ refreshToken: raw, allowLoginCode: true })).rejects.toThrow("revoked legacy");
    }
    expect(tokens.refresh).toHaveBeenCalledTimes(3); expect(codes.redeemLoginCode).not.toHaveBeenCalled(); expect(repository.loginCode).not.toHaveBeenCalled();
    await expect(service.refresh({ refreshToken: token, allowLoginCode: true, consumer: "a1" })).rejects.toThrow("cannot redeem login codes");
    await expect(service.refresh({ refreshToken: token, allowLoginCode: false, consumer: "browser" })).rejects.toThrow("Invalid refresh request");
    await expect(service.refresh({ refreshToken: token, allowLoginCode: false, consumer: "a1" })).rejects.toThrow("revoked legacy");
    expect(tokens.refresh).toHaveBeenLastCalledWith({ refreshToken: token }, {}, "a1");
  });
  it("keeps public refresh on the default consumer even if its body asks for A1", async () => {
    const tokens = { refresh: vi.fn(async () => ({})) };
    const controller = new AuthController(tokens as unknown as TokenIssuanceService);
    await controller.refresh({ refreshToken: token, consumer: "a1" }, {});
    expect(tokens.refresh).toHaveBeenCalledWith({ refreshToken: token, consumer: "a1" }, { idempotencyKey: undefined, ip: null, userAgent: null });
    expect(tokens.refresh.mock.calls[0]).toHaveLength(2);
  });
});
