import { createHash } from "node:crypto";
import type { Connection, PoolConnection, RowDataPacket } from "mysql2/promise";

type Transaction = Connection | PoolConnection;
export const migrationPrimaryKeys:Readonly<Record<string,readonly string[]>> = {
  user:["id"],user_info:["id"],auth_rule:["name"],auth_item:["name"],auth_item_child:["parent","child"],
  auth_assignment:["item_name","user_id"],organization:["id"],user_organization:["user_id","organization_id"],
  wechat:["id"],invitation_record:["id"],invitation:["id"],identity_profile_avatars:["user_id"],identity_legacy_profile_rows:["id"]
};

/** Caller must hold this row lock through the import transaction. The transition is one-way. */
export async function assertMigrationStaging(connection:Transaction):Promise<void> {
  const [rows]=await connection.execute<RowDataPacket[]>("SELECT authority FROM identity_migration_control WHERE id=1 FOR UPDATE");
  if(rows[0]?.authority!=="staging")throw new Error("Identity is already authoritative; importing or syncing legacy data is forbidden. Use a reviewed reverse migration to change authority.");
}
export async function activateIdentityAuthority(connection:Transaction):Promise<void> {
  await connection.execute("SELECT authority FROM identity_migration_control WHERE id=1 FOR UPDATE");
  await connection.execute("UPDATE identity_migration_control SET authority='identity',activated_at=COALESCE(activated_at,UTC_TIMESTAMP(3)) WHERE id=1");
}
export function migrationRowKey(table:string,row:Record<string,unknown>):{keyHash:string;keyJson:string} {
  const keys=migrationPrimaryKeys[table];if(!keys)throw new Error("Unsupported migration table");
  const values=keys.map(key=>{if(row[key]==null)throw new Error(`Missing migration key: ${table}.${key}`);return String(row[key]);});
  const keyJson=JSON.stringify(values);return {keyHash:createHash("sha256").update(keyJson).digest("hex"),keyJson};
}
export function migrationRowHash(row:Record<string,unknown>,columns:readonly string[]):string {
  const values=columns.map(column=>{
    let value=row[column]??null;
    if(["info","payload_json"].includes(column) && typeof value==="string"){try{value=JSON.parse(value);}catch{/* Preserve historical text exactly. */}}
    return [column,normalize(value)];
  });
  return createHash("sha256").update(JSON.stringify(values)).digest("hex");
}
export async function recordMigrationBaseline(connection:Transaction,table:string,columns:readonly string[],source:Record<string,unknown>|null,target:Record<string,unknown>|null):Promise<void> {
  if(!source&&!target)throw new Error("A migration row is required");
  const key=migrationRowKey(table,(source??target)!);
  await connection.execute(`INSERT INTO identity_migration_rows (table_name,key_hash,key_json,columns_json,source_hash,target_hash)
    VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE columns_json=VALUES(columns_json),source_hash=VALUES(source_hash),target_hash=VALUES(target_hash)`,
    [table,key.keyHash,key.keyJson,JSON.stringify(columns),source?migrationRowHash(source,columns):null,target?migrationRowHash(target,columns):null]);
}
function normalize(value:unknown):unknown {
  if(value instanceof Date)return value.toISOString();
  if(Buffer.isBuffer(value))return {binary:value.toString("base64")};
  if(Array.isArray(value))return value.map(normalize);
  if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([key,v])=>[key,normalize(v)]));
  return value;
}
