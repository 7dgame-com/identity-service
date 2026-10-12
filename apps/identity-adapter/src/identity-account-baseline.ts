import { createHash } from "node:crypto";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { accountImportTables } from "./identity-account-import.js";

/** A read-only inventory: no names, addresses, credentials or token values leave the source. */
export async function readAccountBaseline(source: Connection, maxUsers = 100_000) {
  if (!Number.isSafeInteger(maxUsers) || maxUsers < 1 || maxUsers > 1_000_000) throw new Error("Invalid baseline user budget");
  await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  try {
    const tables: Record<string, { rows: number; columns: unknown[]; indexes: unknown[] }> = {};
    const missingTables: string[] = [];
    for (const table of Object.keys(accountImportTables)) {
      const [present] = await source.execute<RowDataPacket[]>("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?",[table]);
      if (!present.length) { missingTables.push(table); continue; }
      const [columns] = await source.execute<RowDataPacket[]>("SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,COLUMN_KEY,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION",[table]);
      const [indexes] = await source.execute<RowDataPacket[]>("SELECT INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY INDEX_NAME,SEQ_IN_INDEX",[table]);
      const [count] = await source.query<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM \`${table}\``);
      tables[table]={rows:Number(count[0].total),columns,indexes};
    }
    if (!tables.user) throw new Error("Source user table is missing");
    const [users] = await source.query<RowDataPacket[]>(`SELECT id,status,CASE WHEN password_hash LIKE '$2y$%' THEN 'bcrypt-2y' WHEN password_hash LIKE '$2b$%' THEN 'bcrypt-2b' WHEN password_hash LIKE '$2a$%' THEN 'bcrypt-2a' WHEN password_hash IS NULL OR password_hash='' THEN 'empty' ELSE 'other' END AS algorithm FROM user ORDER BY id LIMIT ${maxUsers+1}`);
    if(users.length>maxUsers)throw new Error("Baseline exceeds user budget; no truncated result is accepted");
    const userIds=createHash("sha256");const statuses:Record<string,number>={},credentialAlgorithms:Record<string,number>={};
    for(const user of users){userIds.update(`${user.id}\n`);statuses[String(user.status)]=(statuses[String(user.status)]??0)+1;credentialAlgorithms[user.algorithm]=(credentialAlgorithms[user.algorithm]??0)+1;}
    const [foreignKeys]=await source.query<RowDataPacket[]>(`SELECT k.TABLE_NAME,k.COLUMN_NAME,k.CONSTRAINT_NAME,k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE
      FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME
      WHERE k.CONSTRAINT_SCHEMA=DATABASE() AND (k.TABLE_NAME='user' OR k.REFERENCED_TABLE_NAME='user') ORDER BY k.TABLE_NAME,k.CONSTRAINT_NAME,k.ORDINAL_POSITION`);
    return {version:1,capturedAt:new Date().toISOString(),tables,missingTables,
      users:{count:users.length,minId:users.length?Number(users[0].id):null,maxId:users.length?Number(users.at(-1)!.id):null,idSetSha256:userIds.digest("hex"),statuses,credentialAlgorithms},foreignKeys,
      sessions:{audited:false,requiredSources:["Yii Redis refresh records","auth-service OAuth sessions","pending login and WeChat codes"],note:"Export only after old identity writers are drained; this SQL inventory does not inspect Redis or prove production readiness."}};
  } finally { await source.rollback(); }
}
