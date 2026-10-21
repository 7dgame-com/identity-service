import { assertAdmissionWriter } from "./identity-admission.js";
import { allocatorMutation } from "./identity-allocator-state.js";
import { createHash } from "node:crypto";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { assertMigrationStaging } from "./migration-state.js";
import {
  importedChallengePrefix,
  type LegacyChallengeKind,
} from "./legacy-challenge-limits.js";

const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const email = (value: string) => value.trim().toLowerCase();
const userId = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const reviewSchema = z
  .object({
    email: z.string().email(),
    user_id: userId,
    account_email: z.string().email().nullable(),
    review_reference: z.string().trim().min(1).max(255),
  })
  .strict();
const recordSchema = z
  .object({
    key: z.string().min(1).max(512),
    value: z.string().max(4096),
    // These must be collected together on the Redis server, after draining writers.
    redis_time_ms: z.number().int().positive().max(253402300799999),
    pttl_ms: z.number().int().nonnegative().max(1800000),
    expires_at_ms: z.number().int().positive().max(253402300799999),
  })
  .strict();
const codeSchema = z
  .object({
    code: z.string().regex(/^\d{6}$/),
    created_at: z.number().int().nonnegative(),
  })
  .strict();
const resetCodeSchema = codeSchema.extend({
  email: z.string().email(),
  user_id: userId,
});
const resetTokenSchema = resetCodeSchema.omit({ code: true });
const associationSchema = z
  .object({
    issuer: z.literal("yii-email-code-v1"),
    user_id: userId,
    account_email: z.string().email().nullable(),
    target_email: z.string().email(),
    code_hash: z.string().regex(/^[a-f0-9]{64}$/),
    issued_at: z.number().int().nonnegative(),
    expires_at_ms: z.number().int().positive().max(253402300799999),
  })
  .strict();
type Entry = {
  sourceHash: string;
  payloadHash: string;
  kind: LegacyChallengeKind | "reset_token" | "change_token";
  type: "code" | "token" | "attempts" | "rate";
  email: string | null;
  userId: number | null;
  accountEmail: string | null;
  hash: string | null;
  issuedAt: Date | null;
  expiresAt: Date;
  attempts: number;
};
export interface LegacyChallengeSalts {
  passwordReset: string;
  emailVerification: string;
}

/** Offline only. The input contains credentials; errors intentionally omit input values. */
export function normalizeLegacyChallengeManifest(
  payload: unknown,
  salts: LegacyChallengeSalts,
  maxRows = 100000,
): Entry[] {
  if (
    !Number.isSafeInteger(maxRows) ||
    maxRows < 1 ||
    maxRows > 100000 ||
    !salts.passwordReset ||
    !salts.emailVerification
  )
    throw new Error("Invalid challenge import configuration.");
  const manifest = z
    .object({
      version: z.literal(1),
      final_drained_snapshot: z.literal(true),
      records: z.array(recordSchema).max(maxRows),
      reviewed_email_associations: z.array(reviewSchema).max(maxRows),
    })
    .strict()
    .safeParse(payload);
  if (!manifest.success) throw new Error("Invalid offline challenge manifest.");
  const reviews = new Map<string, z.infer<typeof reviewSchema>>();
  for (const review of manifest.data.reviewed_email_associations) {
    const key = email(review.email);
    if (reviews.has(key))
      throw new Error("Duplicate reviewed email association.");
    reviews.set(key, review);
  }
  const associations = new Map<string, z.infer<typeof associationSchema>>();
  const allKeys = new Set<string>();
  const records = manifest.data.records.filter((record) => {
    if (allKeys.has(record.key))
      throw new Error("Duplicate offline Redis key.");
    allKeys.add(record.key);
    const metadataKey = /^identity:legacy_email_challenge:([a-f0-9]{64})$/.exec(
      record.key,
    );
    if (!metadataKey) return true;
    let raw: unknown;
    try {
      raw = JSON.parse(record.value);
    } catch {
      throw new Error("Invalid email association metadata.");
    }
    const parsed = associationSchema.safeParse(raw);
    if (
      !parsed.success ||
      sha(email(parsed.data.target_email)) !== metadataKey[1] ||
      parsed.data.expires_at_ms !== record.expires_at_ms ||
      record.pttl_ms > 900000 ||
      Math.abs(record.expires_at_ms - record.redis_time_ms - record.pttl_ms) >
        1000
    )
      throw new Error("Invalid email association metadata.");
    associations.set(email(parsed.data.target_email), parsed.data);
    return false;
  });
  for (const target of associations.keys())
    if (!records.some((r) => r.key === `email:verify:${target}`))
      throw new Error("Orphan email association metadata.");
  const seen = new Set<string>();
  return records.map((record, index): Entry => {
    const invalid = () =>
      new Error(`Invalid or unproven challenge record ${index + 1}.`);
    const sourceHash = sha(record.key);
    if (seen.has(sourceHash)) throw new Error("Duplicate offline Redis key.");
    seen.add(sourceHash);
    const expiresAt = new Date(record.expires_at_ms);
    if (
      Math.abs(record.expires_at_ms - record.redis_time_ms - record.pttl_ms) >
      1000
    )
      throw invalid();
    if (
      !Number.isFinite(expiresAt.getTime()) ||
      expiresAt.getUTCFullYear() > 9999
    )
      throw invalid();
    const result: Entry = {
      sourceHash,
      payloadHash: "",
      kind: "password_reset",
      type: "code",
      email: null,
      userId: null,
      accountEmail: null,
      hash: null,
      issuedAt: null,
      expiresAt,
      attempts: 0,
    };
    const codeMatch = /^(password:reset:code:|email:verify:)(.+)$/.exec(
      record.key,
    );
    const attemptsMatch =
      /^(password:reset:attempts:|email:verify:attempts:)(.+)$/.exec(
        record.key,
      );
    const rateMatch =
      /^email:ratelimit:(request_reset|send_verification):(.+)$/.exec(
        record.key,
      );
    const changeMatch = /^email:change:token:([1-9]\d*)$/.exec(record.key);
    if (attemptsMatch || rateMatch) {
      const match = (attemptsMatch ?? rateMatch)!;
      result.type = attemptsMatch ? "attempts" : "rate";
      result.kind =
        match[1].startsWith("password:") || match[1] === "request_reset"
          ? "password_reset"
          : "email_verification";
      result.email = email(match[2]);
      if (
        !z.string().email().safeParse(result.email).success ||
        !/^\d+$/.test(record.value)
      )
        throw invalid();
      result.attempts = Number(record.value);
      if (
        !Number.isSafeInteger(result.attempts) ||
        result.attempts < 1 ||
        record.pttl_ms > (attemptsMatch ? 900000 : 60000)
      )
        throw invalid();
    } else if (changeMatch) {
      result.kind = "change_token";
      result.type = "token";
      result.userId = Number(changeMatch[1]);
      const review = [...reviews.values()].find(
        (r) =>
          r.user_id === result.userId &&
          r.account_email !== null &&
          email(r.email) === email(r.account_email),
      );
      if (
        !review ||
        !userId.safeParse(result.userId).success ||
        !/^[A-Za-z0-9_-]{48}$/.test(record.value) ||
        record.pttl_ms > 600000
      )
        throw invalid();
      result.accountEmail = email(review.account_email!);
      // This issuer uses SETEX 600, without renewal or a created_at payload.
      result.issuedAt = new Date(expiresAt.getTime() - 600000);
      result.hash = sha(
        `${salts.emailVerification}\x1f${result.userId}\x1f${record.value}`,
      );
    } else if (codeMatch && !codeMatch[2].startsWith("attempts:")) {
      result.kind =
        codeMatch[1] === "password:reset:code:"
          ? "password_reset"
          : "email_verification";
      result.email = email(codeMatch[2]);
      let value: unknown;
      try {
        value = JSON.parse(record.value);
      } catch {
        throw invalid();
      }
      const data = (
        result.kind === "password_reset" ? resetCodeSchema : codeSchema
      ).safeParse(value);
      if (
        !data.success ||
        !z.string().email().safeParse(result.email).success ||
        record.pttl_ms > 900000
      )
        throw invalid();
      result.issuedAt = new Date(data.data.created_at * 1000);
      if (result.kind === "password_reset") {
        const reset = data.data as z.infer<typeof resetCodeSchema>;
        if (email(reset.email) !== result.email) throw invalid();
        result.userId = reset.user_id;
        result.accountEmail = result.email;
      } else {
        // The old key proves the target email globally, not its requesting user.
        const review = reviews.get(result.email),
          association = associations.get(result.email);
        if (!review && !association) throw invalid();
        if (
          association &&
          (association.code_hash !== sha(data.data.code) ||
            association.issued_at !== data.data.created_at ||
            association.expires_at_ms !== record.expires_at_ms)
        )
          throw invalid();
        if (
          review &&
          association &&
          (review.user_id !== association.user_id ||
            (review.account_email === null
              ? null
              : email(review.account_email)) !==
              (association.account_email === null
                ? null
                : email(association.account_email)))
        )
          throw invalid();
        const proof = (association ?? review)!;
        result.userId = proof.user_id;
        result.accountEmail =
          proof.account_email === null ? null : email(proof.account_email);
      }
      result.hash = sha(
        `${result.kind === "password_reset" ? salts.passwordReset : salts.emailVerification}\x1f${result.email}\x1f${data.data.code}`,
      );
    } else if (/^password:reset:[A-Za-z0-9_-]{32}$/.test(record.key)) {
      result.kind = "reset_token";
      result.type = "token";
      let value: unknown;
      try {
        value = JSON.parse(record.value);
      } catch {
        throw invalid();
      }
      const data = resetTokenSchema.safeParse(value);
      if (!data.success) throw invalid();
      result.email = email(data.data.email);
      result.accountEmail = result.email;
      result.userId = data.data.user_id;
      result.issuedAt = new Date(data.data.created_at * 1000);
      result.hash = sha(record.key.slice("password:reset:".length));
    } else throw invalid();
    if (
      result.issuedAt &&
      (result.issuedAt.getTime() > record.redis_time_ms ||
        result.issuedAt >= expiresAt ||
        !Number.isFinite(result.issuedAt.getTime()))
    )
      throw invalid();
    result.payloadHash = sha(
      JSON.stringify({ ...result, payloadHash: undefined }),
    );
    return result;
  });
}

export async function importLegacyChallenges(
  target: Connection,
  payload: unknown,
  options: {
    apply?: boolean;
    environment?: string;
    maxRows?: number;
    salts?: LegacyChallengeSalts;
    now?: Date;
  } = {},
) {
  assertAdmissionWriter();
  if (
    options.apply &&
    (options.environment ?? process.env.NODE_ENV) !== "staging"
  )
    throw new Error("Challenge import apply requires staging.");
  const config = loadConfig();
  const rows = normalizeLegacyChallengeManifest(
    payload,
    options.salts ?? {
      passwordReset: config.passwordReset.codeHashSalt,
      emailVerification: config.emailVerification.codeHashSalt,
    },
    options.maxRows,
  );
  const report = {
    applied: false,
    total: rows.length,
    imported: 0,
    wouldImport: 0,
    existing: 0,
    expired: rows.filter((row) => row.expiresAt <= (options.now ?? new Date()))
      .length,
  };
  await target.beginTransaction();
  try {
    if(options.apply){await assertMigrationStaging(target);}
    const lock = options.apply ? " FOR UPDATE" : "";
    for (const row of [...rows].sort(
      (a, b) =>
        (a.userId ?? 0) - (b.userId ?? 0) ||
        a.sourceHash.localeCompare(b.sourceHash),
    )) {
      if (row.userId !== null) {
        const [users] = await target.execute<RowDataPacket[]>(
          `SELECT email,status,deleted_at,email_verified_at FROM user WHERE id=?${lock}`,
          [row.userId],
        );
        const user = users[0];
        if (
          !user ||
          user.status !== 10 ||
          user.deleted_at ||
          (user.email === null || !String(user.email).trim()
            ? null
            : email(String(user.email))) !== row.accountEmail ||
          ((row.kind === "password_reset" ||
            row.kind === "reset_token" ||
            row.kind === "change_token") &&
            !user.email_verified_at)
        )
          throw new Error(
            "Challenge account association does not match the private authority.",
          );
      }
      const [ledger] = await target.execute<RowDataPacket[]>(
        `SELECT payload_hash FROM identity_legacy_challenge_imports WHERE source_key_hash=?${lock}`,
        [row.sourceHash],
      );
      if (ledger[0]) {
        if (ledger[0].payload_hash !== row.payloadHash)
          throw new Error("Changed or stale final challenge snapshot.");
        report.existing++;
        continue;
      }
      if (row.type === "attempts" || row.type === "rate") {
        const [limits] = await target.execute<RowDataPacket[]>(
          `SELECT attempts_expires_at,rate_limit_until FROM identity_legacy_challenge_limits WHERE kind=? AND BINARY email=BINARY ?${lock}`,
          [row.kind, row.email],
        );
        const field =
          row.type === "attempts" ? "attempts_expires_at" : "rate_limit_until";
        if (limits[0]?.[field])
          throw new Error("Existing challenge limits cannot be overwritten.");
        if (options.apply) {
          await allocatorMutation(target,()=>target.execute(
            "INSERT IGNORE INTO identity_legacy_challenge_limits (kind,email) VALUES (?,?)",
            [row.kind, row.email],
          ));
          await allocatorMutation(target,()=>target.execute(
            `UPDATE identity_legacy_challenge_limits SET ${field}=?${row.type === "attempts" ? ",attempts=?" : ""} WHERE kind=? AND BINARY email=BINARY ?`,
            row.type === "attempts"
              ? [row.expiresAt, row.attempts, row.kind, row.email]
              : [row.expiresAt, row.kind, row.email],
          ));
        }
      } else {
        const table =
          row.type === "code"
            ? row.kind === "password_reset"
              ? "password_reset_challenges"
              : "email_verification_challenges"
            : row.kind === "reset_token"
              ? "identity_password_reset_tokens"
              : "email_change_tokens";
        const keyColumn =
          row.type === "code"
            ? "challenge_key"
            : row.kind === "reset_token"
              ? "token_hash"
              : "token_key";
        const key =
          row.kind === "reset_token"
            ? row.hash!
            : `${importedChallengePrefix}${row.sourceHash}`;
        const [existing] = await target.execute<RowDataPacket[]>(
          `SELECT ${keyColumn},legacy_user_id FROM ${table} WHERE ${keyColumn}=?${lock}`,
          [key],
        );
        if (existing[0]) {
          if (Number(existing[0].legacy_user_id) !== row.userId)
            throw new Error("Existing challenge owner conflict.");
          // Never overwrite consumed credentials, native attempts or lifetimes.
          report.existing++;
        } else {
          if (row.kind !== "reset_token") {
            const [others] = await target.execute<RowDataPacket[]>(
              `SELECT id FROM ${table} WHERE ${row.type === "code" ? "email=?" : "legacy_user_id=?"} LIMIT 1${lock}`,
              [row.type === "code" ? row.email : row.userId],
            );
            if (others.length)
              throw new Error(
                "A newer native challenge must not be replaced by source state.",
              );
          }
          if (options.apply) {
            if (row.type === "code") {
              const limit = rows.find(
                (r) =>
                  r.type === "attempts" &&
                  r.kind === row.kind &&
                  r.email === row.email,
              );
              await allocatorMutation(target,()=>target.execute(
                `INSERT INTO ${table} (challenge_key,legacy_user_id,email,code_hash,attempts,expires_at,locked_until,created_at) VALUES (?,?,?,?,?,?,?,?)`,
                [
                  key,
                  row.userId,
                  row.email,
                  row.hash,
                  limit?.attempts ?? 0,
                  row.expiresAt,
                  limit && limit.attempts >= 5 ? limit.expiresAt : null,
                  row.issuedAt,
                ],
              ));
            } else if (row.kind === "reset_token")
              await allocatorMutation(target,()=>target.execute(
                "INSERT INTO identity_password_reset_tokens (token_hash,legacy_user_id,email,issued_at,expires_at) VALUES (?,?,?,?,?)",
                [row.hash, row.userId, row.email, row.issuedAt, row.expiresAt],
              ));
            else
              await allocatorMutation(target,()=>target.execute(
                "INSERT INTO email_change_tokens (token_key,legacy_user_id,token_hash,expires_at,created_at) VALUES (?,?,?,?,?)",
                [key, row.userId, row.hash, row.expiresAt, row.issuedAt],
              ));
          }
          report.wouldImport++;
        }
      }
      if (row.type === "attempts" || row.type === "rate") report.wouldImport++;
      if (options.apply) {
        await allocatorMutation(target,()=>target.execute(
          "INSERT INTO identity_legacy_challenge_imports (source_key_hash,payload_hash) VALUES (?,?)",
          [row.sourceHash, row.payloadHash],
        ));
        report.imported++;
      }
    }
    if (options.apply) {
      await target.commit();
      report.applied = true;
    } else await target.rollback();
    return report;
  } catch (error) {
    await target.rollback();
    throw error;
  }
}
