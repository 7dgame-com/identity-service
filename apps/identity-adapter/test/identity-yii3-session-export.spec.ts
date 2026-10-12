import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { exportYii3RefreshSessions } from "../src/identity-yii3-session-export.js";

const OBSERVED = Date.parse("2026-10-12T03:04:05.678Z");
const FIXED_TTL_MS = 2_592_000_000;
const ORDINARY_TOKEN = "a".repeat(64);
const DEVICE_TOKEN = `dsn_${"b".repeat(64)}`;
const ORDINARY_UID = 987654321;
const DEVICE_UID = 987654322;
const DEVICE_SN_ID = 345678901;
const SOURCE = {
  application: "yii3-a1", sourceRevision: "0123456789abcdef0123456789abcdef01234567",
  redisDatabase: 1, keyPrefix: "refresh_token:", fixedTtlSeconds: 2592000,
  expiryPolicy: "setex-on-create-only", namespaceWritersReviewed: true,
};
const DEVICE_VALUE = { version: 1, user_id: DEVICE_UID, auth_method: "device_sn", device_sn_id: DEVICE_SN_ID };
const ABSOLUTE_EXPIRY = { kind: "pexpiretime", observedAtMs: OBSERVED, expiresAtMs: OBSERVED + FIXED_TTL_MS - 54321 };

function entry(token = ORDINARY_TOKEN, value: unknown = String(ORDINARY_UID), expiry: unknown = ABSOLUTE_EXPIRY) {
  return { key: `${SOURCE.keyPrefix}${token}`, value, expiry };
}
function snapshot(entries: unknown[] = [entry()], overrides: Record<string, unknown> = {}) {
  return { version: 1, source: { ...SOURCE }, capturedAtMs: OBSERVED + 123, entries, ...overrides };
}
function hash(token: string): string { return createHash("sha256").update(token).digest("hex"); }

describe("reviewed offline Yii3 refresh-session export", () => {
  it("preserves full absolute milliseconds and derives issuance solely from the reviewed fixed TTL", () => {
    const input = snapshot();
    const result = exportYii3RefreshSessions(input);
    const tokenHash = hash(ORDINARY_TOKEN);
    expect(result.manifest).toEqual({ version: 1, sessions: [{
      keyEncoding: "sha256-hex", key: tokenHash, user_id: ORDINARY_UID, session_id: `yii3:${tokenHash}`,
      created_at: new Date(ABSOLUTE_EXPIRY.expiresAtMs - FIXED_TTL_MS).toISOString(),
      expires_at: new Date(ABSOLUTE_EXPIRY.expiresAtMs).toISOString(), revoked_at: null, client: null,
      yii3: { source: SOURCE, expiry: ABSOLUTE_EXPIRY, capturedAtMs: OBSERVED + 123, credentialKind: "ordinary" },
    }] });
    expect(Date.parse(result.manifest.sessions[0].expires_at as string)).toBe(ABSOLUTE_EXPIRY.expiresAtMs);
    expect(Date.parse(result.manifest.sessions[0].expires_at as string) - Date.parse(result.manifest.sessions[0].created_at as string)).toBe(FIXED_TTL_MS);
    expect(input).toEqual(snapshot());
  });

  it("exports exact v1 SN JSON in either Redis string or decoded-object form", () => {
    for (const value of [JSON.stringify(DEVICE_VALUE), DEVICE_VALUE]) {
      const result = exportYii3RefreshSessions(snapshot([entry(DEVICE_TOKEN, value)]));
      expect(result.manifest.sessions[0]).toMatchObject({
        key: hash(DEVICE_TOKEN), session_id: `yii3:${hash(DEVICE_TOKEN)}`, user_id: DEVICE_UID,
        auth_method: "device_sn", device_sn_id: DEVICE_SN_ID,
        yii3: { credentialKind: "device_sn" },
      });
      expect(result.report).toMatchObject({ total: 1, deviceSessions: 1, ordinarySessions: 0 });
    }
  });

  it("uses the lower TIME+PTTL bound rather than extending to the later Redis TIME", () => {
    const expiry = { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 1234567, timeAfterMs: OBSERVED + 2000 };
    const result = exportYii3RefreshSessions(snapshot([entry(ORDINARY_TOKEN, String(ORDINARY_UID), expiry)], { capturedAtMs: OBSERVED + 2000 }));
    const session = result.manifest.sessions[0];
    expect(Date.parse(session.expires_at as string)).toBe(expiry.timeBeforeMs + expiry.pttlMs);
    expect(Date.parse(session.created_at as string)).toBe(expiry.timeBeforeMs + expiry.pttlMs - FIXED_TTL_MS);
    expect(session.yii3).toMatchObject({ expiry });
    expect(result.report).toMatchObject({ conservativeLifetimes: 1, maxUncertaintyMs: 2000 });
  });

  it("accepts zero-width and zero-remaining-TTL brackets without inventing extra lifetime", () => {
    const expiry = { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 0, timeAfterMs: OBSERVED };
    const result = exportYii3RefreshSessions(snapshot([entry(ORDINARY_TOKEN, String(ORDINARY_UID), expiry)]));
    expect(Date.parse(result.manifest.sessions[0].expires_at as string)).toBe(OBSERVED);
    expect(result.report).toMatchObject({ conservativeLifetimes: 0, maxUncertaintyMs: 0 });
  });

  it("requires the final captured Redis TIME to follow every observation by at most 60000ms", () => {
    expect(exportYii3RefreshSessions(snapshot(undefined, { capturedAtMs: OBSERVED })).manifest.sessions).toHaveLength(1);
    expect(exportYii3RefreshSessions(snapshot(undefined, { capturedAtMs: OBSERVED + 60000 })).manifest.sessions).toHaveLength(1);
    expect(() => exportYii3RefreshSessions(snapshot(undefined, { capturedAtMs: OBSERVED - 1 }))).toThrow();
    expect(() => exportYii3RefreshSessions(snapshot(undefined, { capturedAtMs: OBSERVED + 60001 }))).toThrow();
    const later = entry("c".repeat(64), "123", { ...ABSOLUTE_EXPIRY, observedAtMs: OBSERVED + 124 });
    expect(() => exportYii3RefreshSessions(snapshot([entry(), later]))).toThrow();
    const bracket = { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 60000, timeAfterMs: OBSERVED + 2000 };
    expect(() => exportYii3RefreshSessions(snapshot([entry(ORDINARY_TOKEN, "123", bracket)], { capturedAtMs: OBSERVED + 1999 }))).toThrow();
  });

  it.each([
    { fixedTtlSeconds: 10800 }, { fixedTtlSeconds: 2592001 }, { fixedTtlSeconds: "2592000" },
    { expiryPolicy: "sliding" }, { expiryPolicy: "setex-on-refresh" }, { redisDatabase: 0 }, { redisDatabase: "1" },
    { keyPrefix: "refresh:" }, { keyPrefix: "refresh_token:dsn_" }, { application: "yii2" },
    { namespaceWritersReviewed: false }, { namespaceWritersReviewed: "true" },
    { sourceRevision: "a".repeat(39) }, { sourceRevision: "a".repeat(41) }, { sourceRevision: "A".repeat(40) },
    { sourceRevision: "g".repeat(40) }, { sourceRevision: "reviewed" }, { unreviewedWriter: true },
  ])("rejects unsupported namespace or source-code evidence: %j", (source) => {
    expect(() => exportYii3RefreshSessions(snapshot(undefined, { source: { ...SOURCE, ...source } }))).toThrow();
  });

  it("requires all source proof fields and refuses an unreviewed empty snapshot too", () => {
    for (const key of Object.keys(SOURCE)) {
      const source: Record<string, unknown> = { ...SOURCE };
      delete source[key];
      expect(() => exportYii3RefreshSessions(snapshot([], { source }))).toThrow();
    }
    expect(() => exportYii3RefreshSessions(snapshot([], { source: { ...SOURCE, namespaceWritersReviewed: false } }))).toThrow();
    expect(exportYii3RefreshSessions(snapshot([]))).toMatchObject({
      manifest: { version: 1, sessions: [] }, report: { total: 0, notFinal: true, sourceWrites: 0, targetWrites: 0 },
    });
  });

  it.each([
    { ...ABSOLUTE_EXPIRY, expiresAtMs: OBSERVED + FIXED_TTL_MS + 1 },
    { ...ABSOLUTE_EXPIRY, expiresAtMs: FIXED_TTL_MS - 1 },
    { ...ABSOLUTE_EXPIRY, expiresAtMs: OBSERVED + 123.5 },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: FIXED_TTL_MS + 1, timeAfterMs: OBSERVED },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: -1, timeAfterMs: OBSERVED },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: -2, timeAfterMs: OBSERVED },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 1000.5, timeAfterMs: OBSERVED },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 1000, timeAfterMs: OBSERVED - 1 },
    { kind: "time-pttl-bracket", timeBeforeMs: OBSERVED, pttlMs: 1000, timeAfterMs: OBSERVED + 2001 },
    { kind: "ttl", ttlSeconds: 1000 },
    { ...ABSOLUTE_EXPIRY, pttlMs: 1000 },
  ])("rejects TTL extension, missing-key TTLs and unsupported or unordered expiry evidence: %j", (expiry) => {
    expect(() => exportYii3RefreshSessions(snapshot([entry(ORDINARY_TOKEN, String(ORDINARY_UID), expiry)], { capturedAtMs: OBSERVED + 3000 }))).toThrow();
  });

  it.each([
    "refresh:" + ORDINARY_TOKEN, SOURCE.keyPrefix + "x".repeat(64), SOURCE.keyPrefix + "A".repeat(64),
    SOURCE.keyPrefix + "a".repeat(63), SOURCE.keyPrefix + "a".repeat(65), SOURCE.keyPrefix + "dsn_" + "b".repeat(63),
    SOURCE.keyPrefix + "dsn_dsn_" + "b".repeat(64), SOURCE.keyPrefix + ORDINARY_TOKEN + ":suffix",
    SOURCE.keyPrefix + " " + ORDINARY_TOKEN,
  ])("rejects malformed or falsely prefixed keys: %s", (key) => {
    expect(() => exportYii3RefreshSessions(snapshot([{ ...entry(), key }]))).toThrow();
  });

  it.each([
    "0", "-1", "+1", "01", "1.5", "1e3", " 42", "42\n", "9007199254740992", "", 42, null,
    { user_id: 42 }, DEVICE_VALUE, JSON.stringify(DEVICE_VALUE),
  ])("requires an ordinary credential's canonical scalar UID: %j", (value) => {
    expect(() => exportYii3RefreshSessions(snapshot([entry(ORDINARY_TOKEN, value)]))).toThrow();
  });

  it.each([
    "42", "{", "null", "[]", { ...DEVICE_VALUE, version: 2 }, { ...DEVICE_VALUE, version: "1" },
    { ...DEVICE_VALUE, user_id: "42" }, { ...DEVICE_VALUE, user_id: 0 },
    { ...DEVICE_VALUE, user_id: Number.MAX_SAFE_INTEGER + 1 }, { ...DEVICE_VALUE, auth_method: "password" },
    { ...DEVICE_VALUE, device_sn_id: "73" }, { ...DEVICE_VALUE, device_sn_id: -1 },
    { ...DEVICE_VALUE, device_sn_id: 1.5 }, { ...DEVICE_VALUE, device_sn_id: Number.MAX_SAFE_INTEGER + 1 },
    { ...DEVICE_VALUE, scope: "admin" }, { version: 1, user_id: DEVICE_UID, auth_method: "device_sn" },
    { version: 1, user_id: DEVICE_UID, device_sn_id: DEVICE_SN_ID },
  ])("requires exact paired SN provenance in device values: %j", (value) => {
    expect(() => exportYii3RefreshSessions(snapshot([entry(DEVICE_TOKEN, value)]))).toThrow();
  });

  it("rejects duplicate credentials rather than exporting competing sessions", () => {
    expect(() => exportYii3RefreshSessions(snapshot([entry(), entry()]))).toThrow("Duplicate Yii3 refresh snapshot entry.");
    expect(() => exportYii3RefreshSessions(snapshot([entry(), entry(ORDINARY_TOKEN, "123")]))).toThrow("Duplicate Yii3 refresh snapshot entry.");
    expect(() => exportYii3RefreshSessions(snapshot([entry(DEVICE_TOKEN, DEVICE_VALUE), entry(DEVICE_TOKEN, JSON.stringify(DEVICE_VALUE))]))).toThrow("Duplicate Yii3 refresh snapshot entry.");
  });

  it("hashes the entire credential and keeps session IDs stable across entry order and observations", () => {
    const first = entry(), device = entry(DEVICE_TOKEN, DEVICE_VALUE);
    const exported = exportYii3RefreshSessions(snapshot([first, device])).manifest.sessions;
    const reordered = exportYii3RefreshSessions(snapshot([device, first], { capturedAtMs: OBSERVED + 124 })).manifest.sessions;
    expect(exported.map((session) => session.session_id).sort()).toEqual(reordered.map((session) => session.session_id).sort());
    const sameHexOrdinary = DEVICE_TOKEN.slice(4);
    const separate = exportYii3RefreshSessions(snapshot([entry(sameHexOrdinary), device])).manifest.sessions;
    expect(separate[0].key).toBe(hash(sameHexOrdinary));
    expect(separate[1].key).toBe(hash(DEVICE_TOKEN));
    expect(separate[0].key).not.toBe(separate[1].key);
  });

  it("keeps raw credentials out of the manifest and all PII out of the nonfinal report", () => {
    const result = exportYii3RefreshSessions(snapshot([entry(), entry(DEVICE_TOKEN, JSON.stringify(DEVICE_VALUE))]));
    const manifest = JSON.stringify(result.manifest), report = JSON.stringify(result.report);
    for (const token of [ORDINARY_TOKEN, DEVICE_TOKEN]) {
      expect(manifest).not.toContain(token);
      expect(manifest).not.toContain(`${SOURCE.keyPrefix}${token}`);
      expect(report).not.toContain(token);
      expect(report).not.toContain(hash(token));
    }
    for (const value of [ORDINARY_UID, DEVICE_UID, DEVICE_SN_ID]) expect(report).not.toContain(String(value));
    expect(report).not.toContain(SOURCE.keyPrefix);
    expect(report).not.toContain(JSON.stringify(DEVICE_VALUE));
    expect(result.report).toEqual({ total: 2, deviceSessions: 1, ordinarySessions: 1,
      conservativeLifetimes: 0, maxUncertaintyMs: 0, notFinal: true, sourceWrites: 0, targetWrites: 0 });
    expect(result.manifest.sessions.every((session) => session.keyEncoding === "sha256-hex"
      && /^[a-f0-9]{64}$/.test(session.key as string) && session.session_id === `yii3:${session.key}`)).toBe(true);
  });
});
