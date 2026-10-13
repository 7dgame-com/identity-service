import { allocatorMutation } from "./identity-allocator-state.js";
import { createHash } from "node:crypto";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { assertMigrationStaging } from "./migration-state.js";

const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const integer = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const seconds = z.number().int().nonnegative().max(253402300799);
const text = (max: number) => z.string().min(1).max(max);
const appId = text(128).refine(
  (value) => !["unknown", "legacy-redis"].includes(value.toLowerCase()),
);
const context = z
  .object({
    device: z.string().max(128).optional(),
    source: z.string().max(128).optional(),
    client_version: z.string().max(128).optional(),
    frontend_domain: z.string().max(253).optional(),
  })
  .strict();
const codeSchema = z
  .object({
    code_hash: hex,
    user_id: integer,
    issued_at: seconds,
    expires_at: seconds,
    context: context.default({}),
  })
  .strict()
  .refine(
    (row) =>
      row.expires_at >= row.issued_at && row.expires_at - row.issued_at <= 60,
  );
const sceneSchema = z
  .object({
    scene_hash: hex,
    issued_at: seconds,
    expires_at: seconds,
    provider_app_id: appId,
    open_id: text(255).nullable(),
    user_id: integer.nullable().default(null),
    signup_token_hash: hex.nullable().default(null),
    profile: z.record(z.string(), z.unknown()).nullable().default(null),
  })
  .strict()
  .refine(
    (row) =>
      row.expires_at >= row.issued_at &&
      row.expires_at - row.issued_at <= 30 * 24 * 3600,
  )
  .refine(
    (row) =>
      row.open_id !== null ||
      (row.user_id === null &&
        row.signup_token_hash === null &&
        row.profile === null),
  )
  .refine(
    (row) =>
      row.open_id === null ||
      (row.profile?.openId === row.open_id &&
        row.profile?.providerAppId === row.provider_app_id),
  );
const manifestSchema = z
  .object({
    version: z.literal(1),
    captured_at_ms: integer,
    login_codes: z.array(codeSchema),
    wechat_scenes: z.array(sceneSchema),
  })
  .strict();
export type LegacyQrManifest = z.infer<typeof manifestSchema>;

/** Offline snapshot format. No Redis connection or production database is opened. */
const snapshotSchema = z
  .object({
    version: z.literal(1),
    captured_at_ms: integer,
    login_code_read_mode: z.enum(["database", "redis", "redis-first"]),
    user_linked: z
      .array(
        z
          .object({
            id: integer,
            user_id: integer,
            key: text(4096),
            key_encoding: z.enum(["plain", "sha256-hex"]),
            created_at: z
              .string()
              .regex(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/),
          })
          .strict(),
      )
      .default([]),
    redis_login_codes: z
      .array(
        z
          .object({
            key: text(255),
            value: z.union([
              z.string().max(2048),
              z.record(z.string(), z.unknown()),
            ]),
            pttl_ms: z.number().int().min(0).max(300000),
            redis_time_ms: integer,
          })
          .strict(),
      )
      .default([]),
    pending_wechat_scenes: z
      .array(
        z.union([
          z
            .object({
              scene_hash: hex,
              issued_at: integer,
              expires_at: integer,
              provider_app_id: appId,
              source: text(64).optional(),
            })
            .strict()
            .transform(({ source: _source, ...row }) => row),
          z
            .object({
              scene_digest: hex,
              issued_at: z.string().datetime(),
              expires_at: z.string().datetime(),
              provider_app_id: appId,
            })
            .strict()
            .transform((row) => ({
              scene_hash: row.scene_digest,
              issued_at: Math.floor(Date.parse(row.issued_at) / 1000),
              expires_at: Math.floor(Date.parse(row.expires_at) / 1000),
              provider_app_id: row.provider_app_id,
            })),
        ]),
      )
      .default([]),
    redis_open_ids: z
      .array(
        z
          .object({
            key: text(255),
            token: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
            openid: text(255),
          })
          .strict(),
      )
      .default([]),
    wechat_scenes: z
      .array(
        z
          .object({
            source: z.enum([
              "auth-mysql",
              "redis-with-ticket-evidence",
              "ticket-evidence",
            ]),
            token: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
            scene: text(128).optional(),
            redis_key: text(255).optional(),
            provider_app_id: appId,
            openid: text(255).nullable(),
            created_at: z.string().datetime(),
            expires_at: z.string().datetime(),
            consumed_at: z.string().datetime().nullable(),
            user_id: integer.nullable().optional(),
            signup_token: text(255).nullable().optional(),
            profile_json: z
              .record(z.string(), z.unknown())
              .nullable()
              .optional(),
          })
          .strict(),
      )
      .default([]),
  })
  .strict();

export function exportLegacyQrManifest(
  snapshot: unknown,
  maxRows = 100_000,
): LegacyQrManifest {
  try {
    limit(maxRows);
    const raw = snapshotSchema.parse(snapshot);
    if (
      raw.user_linked.length +
        raw.redis_login_codes.length +
        raw.wechat_scenes.length +
        raw.pending_wechat_scenes.length +
        raw.redis_open_ids.length >
      maxRows
    )
      throw new Error();
    const codes = new Map<string, z.infer<typeof codeSchema>>();
    if (raw.login_code_read_mode !== "database")
      for (const record of raw.redis_login_codes) {
        const hash = record.key.match(
          /^[a-z][a-z0-9:_-]{0,127}:code:([a-f0-9]{64})$/,
        )?.[1];
        const value = z
          .object({
            v: z.literal(1),
            user_id: integer,
            issued_at: integer,
            expires_at: integer,
            purpose: z.literal("web-device-login"),
            issuer: z.literal("main-api"),
            context,
          })
          .strict()
          .parse(
            typeof record.value === "string"
              ? JSON.parse(record.value)
              : record.value,
          );
        if (
          !hash ||
          value.expires_at - value.issued_at !== 60 ||
          value.issued_at * 1000 > record.redis_time_ms ||
          record.redis_time_ms > raw.captured_at_ms
        )
          throw new Error();
        // 300s is retention, not authorization: only PTTL above 240s authorizes devices.
        const expiry = Math.min(
          value.expires_at,
          Math.floor(
            (record.redis_time_ms + Math.max(0, record.pttl_ms - 240000)) /
              1000,
          ),
        );
        put(
          codes,
          hash,
          codeSchema.parse({
            code_hash: hash,
            user_id: value.user_id,
            issued_at: value.issued_at,
            expires_at: expiry,
            context: value.context,
          }),
        );
      }
    if (raw.login_code_read_mode !== "redis") {
      const latest = new Map<number, (typeof raw.user_linked)[number]>();
      for (const row of raw.user_linked)
        if (!latest.has(row.user_id) || latest.get(row.user_id)!.id < row.id)
          latest.set(row.user_id, row);
      for (const row of latest.values()) {
        const hash =
          row.key_encoding === "plain" ? digest(row.key) : hex.parse(row.key);
        if (codes.has(hash)) continue; // Redis-first never revives an expired Redis hit via DB fallback.
        const issued = Math.floor(
          Date.parse(`${row.created_at.replace(" ", "T")}+08:00`) / 1000,
        );
        if (
          !Number.isFinite(issued) ||
          issued * 1000 > raw.captured_at_ms ||
          new Date((issued + 8 * 3600) * 1000)
            .toISOString()
            .slice(0, 19)
            .replace("T", " ") !== row.created_at
        )
          throw new Error();
        put(
          codes,
          hash,
          codeSchema.parse({
            code_hash: hash,
            user_id: row.user_id,
            issued_at: issued,
            expires_at: issued + 60,
            context: {},
          }),
        );
      }
    }
    const scenes = new Map<string, z.infer<typeof sceneSchema>>();
    for (const row of raw.pending_wechat_scenes) {
      if (row.issued_at * 1000 > raw.captured_at_ms) throw new Error();
      put(
        scenes,
        row.scene_hash,
        sceneSchema.parse({
          ...row,
          open_id: null,
          user_id: null,
          signup_token_hash: null,
          profile: null,
        }),
      );
    }
    for (const row of raw.redis_open_ids) {
      if (row.key !== yiiOpenIdKey(row.token)) throw new Error();
      const key = digest(row.token),
        pending = scenes.get(key);
      if (
        !pending ||
        (pending.open_id !== null && pending.open_id !== row.openid)
      )
        throw new Error();
      scenes.set(
        key,
        sceneSchema.parse({
          ...pending,
          open_id: row.openid,
          profile: {
            providerAppId: pending.provider_app_id,
            openId: row.openid,
          },
        }),
      );
    }
    for (const row of raw.wechat_scenes) {
      if (row.scene !== undefined && row.scene !== row.token) throw new Error();
      if (row.source === "ticket-evidence" && row.openid !== null)
        throw new Error();
      if (row.source !== "ticket-evidence" && row.openid === null)
        throw new Error();
      if (row.source === "redis-with-ticket-evidence") {
        if (row.redis_key !== yiiOpenIdKey(row.token)) throw new Error();
      }
      const issued = Math.floor(Date.parse(row.created_at) / 1000),
        expiry = Math.floor(Date.parse(row.expires_at) / 1000);
      if (issued * 1000 > raw.captured_at_ms) throw new Error();
      const consumed =
        row.consumed_at === null
          ? expiry
          : Math.floor(Date.parse(row.consumed_at) / 1000);
      if (
        consumed < issued ||
        consumed > expiry ||
        consumed * 1000 > raw.captured_at_ms
      ) {
        if (row.consumed_at !== null) throw new Error();
      }
      const hash = digest(row.token);
      const pending = scenes.get(hash);
      if (
        pending &&
        (pending.provider_app_id !== row.provider_app_id ||
          (pending.open_id && pending.open_id !== row.openid))
      )
        throw new Error();
      // A signed, already-scanned MySQL state has its own original login window. Pending metadata supplies no new lifetime.
      if (pending && pending.open_id !== null) scenes.delete(hash);
      if (pending && pending.open_id === null && row.openid !== null)
        scenes.delete(hash);
      put(
        scenes,
        hash,
        sceneSchema.parse({
          scene_hash: hash,
          issued_at: issued,
          expires_at: Math.min(expiry, consumed),
          provider_app_id: row.provider_app_id,
          open_id: row.openid,
          user_id: row.user_id ?? null,
          signup_token_hash: row.signup_token ? digest(row.signup_token) : null,
          profile: row.openid
            ? {
                ...row.profile_json,
                providerAppId: row.provider_app_id,
                openId: row.openid,
              }
            : null,
        }),
      );
    }
    return manifestSchema.parse({
      version: 1,
      captured_at_ms: raw.captured_at_ms,
      login_codes: [...codes.values()],
      wechat_scenes: [...scenes.values()],
    });
  } catch {
    throw new Error(
      "Invalid offline QR snapshot or missing trustworthy TTL/provider evidence.",
    );
  }
}

export async function importLegacyQrManifest(
  target: Connection,
  payload: unknown,
  options: {
    apply?: boolean;
    environment?: string;
    maxRows?: number;
    now?: number;
  } = {},
) {
  if (
    options.apply &&
    (options.environment ?? process.env.NODE_ENV) !== "staging"
  )
    throw new Error("Legacy QR state may only be applied in staging.");
  let manifest: LegacyQrManifest;
  try {
    limit(options.maxRows ?? 100_000);
    manifest = manifestSchema.parse(payload);
    if (
      manifest.login_codes.length + manifest.wechat_scenes.length >
      (options.maxRows ?? 100_000)
    )
      throw new Error();
    if (
      [...manifest.login_codes, ...manifest.wechat_scenes].some(
        (row) => row.issued_at * 1000 > manifest.captured_at_ms,
      )
    )
      throw new Error();
    const codes = new Map<string, unknown>(),
      scenes = new Map<string, unknown>();
    for (const row of manifest.login_codes) put(codes, row.code_hash, row);
    for (const row of manifest.wechat_scenes) put(scenes, row.scene_hash, row);
    if (
      codes.size !== manifest.login_codes.length ||
      scenes.size !== manifest.wechat_scenes.length
    )
      throw new Error();
  } catch {
    throw new Error("Invalid legacy QR manifest.");
  }
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const report = {
    applied: false,
    loginCodes: manifest.login_codes.length,
    wechatScenes: manifest.wechat_scenes.length,
    wouldImport: 0,
    imported: 0,
    existing: 0,
    inactive: 0,
  };
  await target.beginTransaction();
  try {
    if(options.apply){await assertMigrationStaging(target);}
    const lock = options.apply ? " FOR UPDATE" : "";
    for (const row of [...manifest.login_codes].sort(
      (a, b) => a.user_id - b.user_id || a.code_hash.localeCompare(b.code_hash),
    )) {
      const [users] = await target.execute<RowDataPacket[]>(
        `SELECT id FROM user WHERE id=?${lock}`,
        [row.user_id],
      );
      if (!users[0])
        throw new Error("QR manifest references a missing private account.");
      const [known] = await target.execute<RowDataPacket[]>(
        `SELECT user_id FROM identity_login_codes WHERE code_hash=?${lock}`,
        [row.code_hash],
      );
      if (known[0]) {
        if (Number(known[0].user_id) !== row.user_id)
          throw new Error("Existing QR account conflict.");
        report.existing++;
        continue;
      }
      if (row.expires_at <= now) report.inactive++;
      report.wouldImport++;
      if (options.apply)
        await allocatorMutation(target,()=>target.execute(
          "INSERT INTO identity_login_codes(code_hash,user_id,issued_at,expires_at,context_json) VALUES (?,?,?,?,?)",
          [
            row.code_hash,
            row.user_id,
            row.issued_at,
            row.expires_at,
            JSON.stringify(row.context),
          ],
        ));
    }
    for (const row of [...manifest.wechat_scenes].sort((a, b) =>
      a.scene_hash.localeCompare(b.scene_hash),
    )) {
      const [known] = await target.execute<RowDataPacket[]>(
        `SELECT provider_app_id,open_id FROM identity_wechat_scenes WHERE scene_hash=?${lock}`,
        [row.scene_hash],
      );
      if (known[0]) {
        if (
          (known[0].provider_app_id &&
            known[0].provider_app_id !== row.provider_app_id) ||
          (known[0].open_id && known[0].open_id !== row.open_id)
        )
          throw new Error("Existing QR provider subject conflict.");
        report.existing++;
        continue;
      }
      let userId = row.user_id,
        signupHash = row.signup_token_hash;
      if (row.open_id) {
        const [bindings] = await target.execute<RowDataPacket[]>(
          `SELECT user_id FROM identity_wechat_identities WHERE provider='wechat_official_account' AND provider_app_id=? AND open_id=?${lock}`,
          [row.provider_app_id, row.open_id],
        );
        const [legacy] = await target.execute<RowDataPacket[]>(
          `SELECT user_id,token FROM wechat WHERE openid=?${lock}`,
          [row.open_id],
        );
        const ids = new Set(
          [...bindings, ...legacy]
            .filter((binding) => binding.user_id !== null)
            .map((binding) => Number(binding.user_id)),
        );
        if (userId !== null) ids.add(userId);
        if (ids.size > 1)
          throw new Error("QR manifest provider account mapping conflict.");
        userId = ids.size ? [...ids][0] : null;
        if (userId !== null) signupHash = null;
        if (userId === null && legacy[0]?.token) {
          const stored = digest(String(legacy[0].token));
          if (signupHash && signupHash !== stored)
            throw new Error("QR manifest registration credential conflict.");
          signupHash = stored;
        }
      }
      if (userId !== null) {
        const [users] = await target.execute<RowDataPacket[]>(
          `SELECT id FROM user WHERE id=?${lock}`,
          [userId],
        );
        if (!users[0])
          throw new Error("QR manifest references a missing private account.");
      }
      if (row.expires_at <= now) report.inactive++;
      report.wouldImport++;
      if (options.apply)
        await allocatorMutation(target,()=>target.execute(
          "INSERT INTO identity_wechat_scenes(scene_hash,expires_at,provider_app_id,open_id,user_id,signup_token_hash,profile_json) VALUES (?,?,?,?,?,?,?)",
          [
            row.scene_hash,
            row.expires_at,
            row.provider_app_id,
            row.open_id,
            userId,
            signupHash,
            row.profile ? JSON.stringify(row.profile) : null,
          ],
        ));
    }
    if (options.apply) {
      await target.commit();
      report.applied = true;
      report.imported = report.wouldImport;
    } else await target.rollback();
    return report;
  } catch (error) {
    await target.rollback();
    throw error;
  }
}
function put<T>(rows: Map<string, T>, key: string, row: T) {
  if (rows.has(key) && JSON.stringify(rows.get(key)) !== JSON.stringify(row))
    throw new Error("Conflicting offline QR rows.");
  rows.set(key, row);
}
function limit(value: number) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 100_000)
    throw new Error("Invalid QR import size limit.");
}
function yiiOpenIdKey(token: string) {
  const key =
    /^[A-Za-z0-9]+$/.test(token) && Buffer.byteLength(token) <= 32
      ? token
      : createHash("md5").update(token).digest("hex");
  return `open_id:a:${key}`;
}
