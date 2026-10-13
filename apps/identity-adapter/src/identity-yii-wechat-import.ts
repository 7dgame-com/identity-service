import { allocatorMutation } from "./identity-allocator-state.js";
import { createHash } from "node:crypto";
import type { Connection, PoolConnection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { assertMigrationStaging } from "./migration-state.js";
import { enqueueSubjectEvent } from "./subject-events.js";

const bindingSchema = z
  .object({
    provider: z.enum([
      "wechat_official_account",
      "wechat_website",
      "wechat_mini_program",
    ]),
    provider_app_id: z.string().min(1).max(191),
    open_id: z.string().min(1).max(191),
    user_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    union_id: z.string().min(1).max(191).nullable().default(null),
    evidence: z.enum(["wechat", "user.wx_openid"]),
  })
  .strict();
const manifestSchema = z
  .object({
    schema_version: z.literal(1),
    source_database: z.string().min(1).max(255),
    review: z
      .object({
        reference: z.string().min(1).max(255),
        reviewed_by: z.string().min(1).max(255),
        reviewed_at: z.string().datetime(),
      })
      .strict(),
    bindings: z.array(bindingSchema).min(1).max(100000),
  })
  .strict();
type ReviewedBinding = z.infer<typeof bindingSchema>;

/** An operator-reviewed app mapping supplements Yii's otherwise unscoped identifiers. */
export async function importReviewedYiiWechatBindings(
  source: Connection,
  target: Connection,
  input: unknown,
  options: { importKey: string; apply?: boolean; maxRows?: number },
) {
  if (source === target || !/^[A-Za-z0-9_.:-]{1,160}$/.test(options.importKey))
    throw new Error("Invalid reviewed WeChat import configuration");
  const manifest = manifestSchema.parse(input);
  const maxRows = options.maxRows ?? 10000;
  if (
    !Number.isSafeInteger(maxRows) ||
    maxRows < 1 ||
    maxRows > 100000 ||
    manifest.bindings.length > maxRows
  )
    throw new Error("Reviewed WeChat import exceeds its explicit bound");
  if (new Date(manifest.review.reviewed_at).getTime() > Date.now() + 300000)
    throw new Error("Manifest review timestamp is in the future");
  manifest.bindings.sort((a, b) =>
    tuple(a) < tuple(b) ? -1 : tuple(a) > tuple(b) ? 1 : 0,
  );
  if (new Set(manifest.bindings.map(tuple)).size !== manifest.bindings.length)
    throw new Error("Duplicate reviewed provider tuples are forbidden");
  const manifestDigest = createHash("sha256")
    .update(JSON.stringify(manifest))
    .digest("hex");
  const [sourceNames] = await source.query<RowDataPacket[]>(
    "SELECT DATABASE() AS name",
  );
  if (sourceNames[0]?.name !== manifest.source_database)
    throw new Error("Reviewed manifest source database does not match");
  const [targetNames] = await target.query<RowDataPacket[]>(
    "SELECT DATABASE() AS name",
  );
  if (targetNames[0]?.name === manifest.source_database)
    throw new Error("Legacy and private Identity database names must differ");
  await assertWechatBinarySchema(target);
  const report = {
    applied: false,
    replay: false,
    bindings: manifest.bindings.length,
    wouldImport: 0,
    existing: 0,
    imported: 0,
  };
  await target.beginTransaction();
  let sourceStarted = false;
  try {
    await assertMigrationStaging(target);    const [runs] = await target.execute<RowDataPacket[]>(
      "SELECT source_database,row_counts FROM identity_wechat_import_runs WHERE import_key=? FOR UPDATE",
      [options.importKey],
    );
    if (runs[0]) {
      const counts =
        typeof runs[0].row_counts === "string"
          ? JSON.parse(runs[0].row_counts)
          : runs[0].row_counts;
      if (
        runs[0].source_database !== manifest.source_database ||
        counts?.kind !== "reviewed-yii-wechat-v1" ||
        counts.manifest_digest !== manifestDigest
      )
        throw new Error("Import key belongs to another reviewed manifest");
      await target.rollback();
      return { ...report, replay: true, existing: manifest.bindings.length };
    }
    await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
    sourceStarted = true;
    const changes: ReviewedBinding[] = [];
    for (const binding of manifest.bindings) {
      const [users] = await source.execute<RowDataPacket[]>(
        "SELECT id,username,wx_openid FROM user WHERE id=?",
        [binding.user_id],
      );
      const oldUser = users[0];
      if (!oldUser) throw new Error("Reviewed source user does not exist");
      if (binding.evidence === "wechat") {
        const [proofs] = await source.execute<RowDataPacket[]>(
          "SELECT openid,unionid,user_id FROM wechat WHERE BINARY openid=BINARY ?",
          [binding.open_id],
        );
        if (
          proofs.length !== 1 ||
          proofs[0].openid !== binding.open_id ||
          Number(proofs[0].user_id) !== binding.user_id ||
          (binding.union_id !== null && proofs[0].unionid !== binding.union_id)
        )
          throw new Error("Reviewed source WeChat proof does not match");
      } else {
        const [owners] = await source.execute<RowDataPacket[]>(
          "SELECT id FROM user WHERE BINARY wx_openid=BINARY ?",
          [binding.open_id],
        );
        if (
          oldUser.wx_openid !== binding.open_id ||
          owners.length !== 1 ||
          Number(owners[0].id) !== binding.user_id ||
          binding.union_id !== null
        )
          throw new Error("Reviewed source scalar proof does not match");
      }
      const [usersInTarget] = await target.execute<RowDataPacket[]>(
        "SELECT id,username FROM user WHERE id=? FOR UPDATE",
        [binding.user_id],
      );
      if (!usersInTarget[0] || usersInTarget[0].username !== oldUser.username)
        throw new Error("Reviewed canonical account is absent or changed");
      const [known] = await target.execute<RowDataPacket[]>(
        `SELECT provider,provider_app_id,open_id,user_id,union_id FROM identity_wechat_identities
        WHERE BINARY provider=BINARY ? AND BINARY provider_app_id=BINARY ? AND BINARY open_id=BINARY ? FOR UPDATE`,
        [binding.provider, binding.provider_app_id, binding.open_id],
      );
      if (
        known[0] &&
        (known[0].provider !== binding.provider ||
          known[0].provider_app_id !== binding.provider_app_id ||
          known[0].open_id !== binding.open_id ||
          (known[0].user_id != null &&
            Number(known[0].user_id) !== binding.user_id) ||
          (known[0].union_id != null &&
            binding.union_id !== null &&
            known[0].union_id !== binding.union_id))
      )
        throw new Error(
          "Reviewed exact provider binding conflicts with the target",
        );
      const [other] = await target.execute<RowDataPacket[]>(
        `SELECT open_id FROM identity_wechat_identities
        WHERE BINARY provider=BINARY ? AND BINARY provider_app_id=BINARY ? AND user_id=? FOR UPDATE`,
        [binding.provider, binding.provider_app_id, binding.user_id],
      );
      if (other.some((row) => row.open_id !== binding.open_id))
        throw new Error(
          "Canonical account already has another binding in this application",
        );
      if (
        known[0]?.user_id != null &&
        (binding.union_id === null || known[0].union_id === binding.union_id)
      )
        report.existing++;
      else {
        report.wouldImport++;
        changes.push(binding);
      }
    }
    // A reviewed batch cannot assign two openids to one account/application either.
    const owners = new Map<string, string>();
    for (const binding of manifest.bindings) {
      const owner = JSON.stringify([
        binding.provider,
        binding.provider_app_id,
        binding.user_id,
      ]);
      if (owners.has(owner) && owners.get(owner) !== binding.open_id)
        throw new Error(
          "Reviewed account has conflicting application bindings",
        );
      owners.set(owner, binding.open_id);
    }
    if (options.apply) {
      for (const binding of changes)
        await allocatorMutation(target,()=>target.execute(
          `INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id,union_id)
        VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),union_id=COALESCE(union_id,VALUES(union_id)),signup_token_hash=NULL`,
          [
            binding.provider,
            binding.provider_app_id,
            binding.open_id,
            binding.user_id,
            binding.union_id,
          ],
        ));
      for (const userId of [
        ...new Set(changes.map((binding) => binding.user_id)),
      ].sort((a, b) => a - b))
        await enqueueSubjectEvent(target as unknown as PoolConnection, userId);
      await allocatorMutation(target,()=>target.execute(
        "INSERT INTO identity_wechat_import_runs(import_key,source_database,row_counts,completed_at) VALUES(?,?,?,UTC_TIMESTAMP(3))",
        [
          options.importKey,
          manifest.source_database,
          JSON.stringify({
            kind: "reviewed-yii-wechat-v1",
            bindings: manifest.bindings.length,
            manifest_digest: manifestDigest,
          }),
        ],
      ));
      await target.commit();
      report.applied = true;
      report.imported = changes.length;
    } else await target.rollback();
    return report;
  } catch (error) {
    await target.rollback();
    throw error;
  } finally {
    if (sourceStarted) await source.rollback();
  }
}

function tuple(binding: ReviewedBinding) {
  return JSON.stringify([
    binding.provider,
    binding.provider_app_id,
    binding.open_id,
  ]);
}
export async function assertWechatBinarySchema(target: Connection) {
  const [columns] = await target.query<
    RowDataPacket[]
  >(`SELECT TABLE_NAME,COLUMN_NAME,COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()
    AND ((TABLE_NAME='user' AND COLUMN_NAME='wx_openid')
      OR (TABLE_NAME='identity_wechat_identities' AND COLUMN_NAME IN ('provider','provider_app_id','open_id','union_id'))
      OR (TABLE_NAME='wechat' AND COLUMN_NAME IN ('openid','unionid','token'))
      OR (TABLE_NAME='identity_wechat_scenes' AND COLUMN_NAME IN ('provider_app_id','open_id')))`);
  if (
    columns.length !== 10 ||
    columns.some((column) => column.COLLATION_NAME !== "utf8mb4_bin")
  )
    throw new Error(
      "Apply the private WeChat binary schema migration before importing reviewed bindings",
    );
}
