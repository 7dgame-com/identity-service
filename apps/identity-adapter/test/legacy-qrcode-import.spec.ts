import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { exportLegacyQrManifest } from "../src/legacy-qrcode-import.js";

const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const issued = 1780000000,
  captured = (issued + 10) * 1000;
const wallClock = (second: number) =>
  new Date((second + 8 * 3600) * 1000)
    .toISOString()
    .slice(0, 19)
    .replace("T", " ");
const linked = (id = 1, overrides: Record<string, unknown> = {}) => ({
  id,
  user_id: 24,
  key: hash(`device-${id}`),
  key_encoding: "sha256-hex",
  created_at: wallClock(issued),
  ...overrides,
});
const redis = (overrides: Record<string, unknown> = {}) => ({
  key: `auth:login-code:v1:code:${hash("redis-device")}`,
  pttl_ms: 290000,
  redis_time_ms: captured,
  value: {
    v: 1,
    user_id: 24,
    issued_at: issued,
    expires_at: issued + 60,
    purpose: "web-device-login",
    issuer: "main-api",
    context: { frontend_domain: "example.test" },
  },
  ...overrides,
});
const snapshot = (overrides: Record<string, unknown> = {}) => ({
  version: 1,
  captured_at_ms: captured,
  login_code_read_mode: "database",
  user_linked: [],
  redis_login_codes: [],
  wechat_scenes: [],
  ...overrides,
});
const scene = (overrides: Record<string, unknown> = {}) => ({
  source: "auth-mysql",
  token: "old-scene",
  scene: "old-scene",
  provider_app_id: "wx-official",
  openid: "official-openid",
  created_at: new Date(issued * 1000).toISOString(),
  expires_at: new Date((issued + 3600) * 1000).toISOString(),
  consumed_at: null,
  ...overrides,
});
describe("offline legacy QR snapshot export", () => {
  it("selects only the latest database row per user, converts Shanghai time explicitly and retains exact digest", () => {
    const result = exportLegacyQrManifest(
      snapshot({ user_linked: [linked(1), linked(3), linked(2)] }),
    );
    expect(result.login_codes).toEqual([
      {
        code_hash: hash("device-3"),
        user_id: 24,
        issued_at: issued,
        expires_at: issued + 60,
        context: {},
      },
    ]);
  });
  it("hashes declared plaintext even when the historical code happens to contain only hex characters", () => {
    const key = "a".repeat(64);
    const result = exportLegacyQrManifest(
      snapshot({ user_linked: [linked(1, { key, key_encoding: "plain" })] }),
    );
    expect(result.login_codes[0].code_hash).toBe(hash(key));
  });
  it("imports every Redis multi-device code without extending its 60-second authorization window", () => {
    const result = exportLegacyQrManifest(
      snapshot({
        login_code_read_mode: "redis",
        user_linked: [linked()],
        redis_login_codes: [
          redis(),
          redis({
            key: `auth:login-code:v1:code:${hash("second")}`,
            pttl_ms: 275000,
          }),
        ],
      }),
    );
    expect(result.login_codes).toHaveLength(2);
    expect(result.login_codes[0]).toMatchObject({
      expires_at: issued + 60,
      context: { frontend_domain: "example.test" },
    });
    expect(result.login_codes[1].expires_at).toBe(issued + 45);
  });
  it("never revives an expired Redis-first hit from its still-current database shadow", () => {
    const result = exportLegacyQrManifest(
      snapshot({
        login_code_read_mode: "redis-first",
        user_linked: [linked(1, { key: hash("redis-device") })],
        redis_login_codes: [redis({ pttl_ms: 240000 })],
      }),
    );
    expect(result.login_codes).toHaveLength(1);
    expect(result.login_codes[0].expires_at).toBe(issued + 10);
  });
  it("preserves scanned subjects, original expiry, registration digest and provider evidence", () => {
    const result = exportLegacyQrManifest(
      snapshot({
        wechat_scenes: [
          scene({
            signup_token: "pending-signup",
            profile_json: { nickname: "User" },
          }),
        ],
      }),
    );
    expect(result.wechat_scenes[0]).toMatchObject({
      scene_hash: hash("old-scene"),
      expires_at: issued + 3600,
      open_id: "official-openid",
      provider_app_id: "wx-official",
      signup_token_hash: hash("pending-signup"),
      profile: {
        nickname: "User",
        openId: "official-openid",
        providerAppId: "wx-official",
      },
    });
    expect(JSON.stringify(result)).not.toContain("pending-signup");
  });
  it("imports a still-pending ticket only with explicit issued/expiry evidence and never makes a consumed ticket active", () => {
    const result = exportLegacyQrManifest(
      snapshot({
        wechat_scenes: [
          scene({ source: "ticket-evidence", openid: null }),
          scene({
            token: "consumed",
            scene: "consumed",
            consumed_at: new Date((issued + 5) * 1000).toISOString(),
          }),
        ],
      }),
    );
    expect(result.wechat_scenes[0]).toMatchObject({
      open_id: null,
      profile: null,
      expires_at: issued + 3600,
    });
    expect(result.wechat_scenes[1].expires_at).toBe(issued + 5);
  });
  it("validates the actual Yii Redis hash key and preserves external ticket expiry evidence", () => {
    const token = "legacy_scene-with-dashes";
    const redisKey = `open_id:a:${createHash("md5").update(token).digest("hex")}`;
    const row = scene({
      source: "redis-with-ticket-evidence",
      token,
      scene: token,
      redis_key: redisKey,
    });
    expect(
      exportLegacyQrManifest(snapshot({ wechat_scenes: [row] }))
        .wechat_scenes[0].scene_hash,
    ).toBe(hash(token));
    expect(() =>
      exportLegacyQrManifest(
        snapshot({ wechat_scenes: [{ ...row, redis_key: "open_id:a:wrong" }] }),
      ),
    ).toThrow("Invalid offline QR snapshot");
  });
  it("rejects a syntactically shaped but invalid Shanghai wall-clock date", () => {
    expect(() =>
      exportLegacyQrManifest(
        snapshot({
          user_linked: [linked(1, { created_at: "2026-02-31 12:00:00" })],
        }),
      ),
    ).toThrow("Invalid offline QR snapshot");
  });
  it("imports digest-only compatibility baseline pending metadata without knowing the original token", () => {
    const result = exportLegacyQrManifest(
      snapshot({
        pending_wechat_scenes: [
          {
            scene_hash: hash("unscanned"),
            issued_at: issued,
            expires_at: issued + 3600,
            provider_app_id: "wx-official",
            source: "api-site",
          },
        ],
      }),
    );
    expect(result.wechat_scenes[0]).toMatchObject({
      scene_hash: hash("unscanned"),
      open_id: null,
      expires_at: issued + 3600,
    });
    const actual = exportLegacyQrManifest(
      snapshot({
        pending_wechat_scenes: [
          {
            scene_digest: hash("unscanned"),
            issued_at: new Date(issued * 1000).toISOString(),
            expires_at: new Date((issued + 3600) * 1000).toISOString(),
            provider_app_id: "wx-official",
          },
        ],
      }),
    );
    expect(actual.wechat_scenes).toEqual(result.wechat_scenes);
  });
  it("joins actual Redis token/openid hashes to baseline metadata and rejects unproven historic state", () => {
    const row = {
      key: "open_id:a:oldScene",
      token: "oldScene",
      openid: "scanned-openid",
    };
    expect(() =>
      exportLegacyQrManifest(snapshot({ redis_open_ids: [row] })),
    ).toThrow("Invalid offline QR snapshot");
    const result = exportLegacyQrManifest(
      snapshot({
        redis_open_ids: [row],
        pending_wechat_scenes: [
          {
            scene_hash: hash(row.token),
            issued_at: issued,
            expires_at: issued + 3600,
            provider_app_id: "wx-official",
          },
        ],
      }),
    );
    expect(result.wechat_scenes[0]).toMatchObject({
      open_id: "scanned-openid",
      expires_at: issued + 3600,
    });
  });
  it.each([
    {
      wechat_scenes: [
        scene({ source: "redis-with-ticket-evidence", expires_at: undefined }),
      ],
    },
    { wechat_scenes: [scene({ expires_at: "9999-12-31T23:59:59.999Z" })] },
    { wechat_scenes: [scene({ scene: "another-scene" })] },
    { wechat_scenes: [scene({ provider_app_id: "" })] },
    { user_linked: [linked(1, { key_encoding: undefined })] },
    {
      login_code_read_mode: "redis",
      redis_login_codes: [redis({ pttl_ms: -1 })],
    },
    {
      login_code_read_mode: "redis",
      redis_login_codes: [redis({ pttl_ms: 300001 })],
    },
    {
      login_code_read_mode: "redis",
      redis_login_codes: [redis({ key: "wrong-key" })],
    },
    {
      login_code_read_mode: "redis",
      redis_login_codes: [redis({ value: { user_id: 24 } })],
    },
  ])(
    "rejects missing time/provider evidence or corrupt Redis records without leaking QR values",
    (override) => {
      expect(() => exportLegacyQrManifest(snapshot(override))).toThrow(
        "Invalid offline QR snapshot",
      );
    },
  );
});
