import { createHash } from "node:crypto";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { accountImportTables } from "./identity-account-import-tables.js";
import { migrationPrimaryKeys, migrationRowHash, migrationRowKey } from "./migration-state.js";
import { allocatorDigest } from "./identity-allocator-manifest.js";
import { readSourceAllocatorInventory } from "./identity-allocator-finalizer.js";
import { assertProfileJsonValues, legacyProfileJsonTypeSelection } from "./identity-profile-source.js";
import type { ProfileSelectionManifest } from "./identity-profile-migration.js";

const database = "bujiaban_development";
const serverUuid = "1c6c32c4-00a9-11f1-9d18-0c42a14c701e";
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const utc = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(v => Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v);
export const sourceFingerprintSchema = z.object({
  version: z.literal(1), kind: z.literal("identity-account-source-fingerprint"), database: z.literal(database), serverUuid: z.literal(serverUuid),
  profileSelectionSha256: hash.nullable(), maxRows: z.number().int().min(1).max(1000000), schemaSha256: hash, rowsSha256: hash,
  allocatorMetadataSha256: hash, allocatorStateSha256: hash, observedAt: utc,
}).strict();
export type SourceFingerprint = z.infer<typeof sourceFingerprintSchema>;
declare const expectedBrand: unique symbol;
export type ExpectedSourceFingerprint = { readonly [expectedBrand]: true };
const expected = new WeakMap<ExpectedSourceFingerprint, { manifest: SourceFingerprint; profileCanonical: string }>();
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");
export class SourceFingerprintError extends Error {
  constructor(readonly code: string) { super(code); this.name = "SourceFingerprintError"; }
}
function fail(code: string): never { throw new SourceFingerprintError(code); }
function json(bytes: Buffer, max: number): unknown {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > max || !Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("SOURCE_FINGERPRINT_INPUT_INVALID");
  return JSON.parse(bytes.toString("utf8"));
}
/** A data binding, never an admission permission. No caller callback or path. */
export function prepareExpectedSourceFingerprint(bytes: Buffer, profileBytes: Buffer | null, maxRows: number): ExpectedSourceFingerprint {
  const parsed = sourceFingerprintSchema.safeParse(json(Buffer.from(bytes), 16 * 1024 * 1024));
  if (!parsed.success) fail("SOURCE_FINGERPRINT_FORMAT_NOT_WIRED");
  const manifest = parsed.data;
  if (manifest.maxRows !== maxRows || manifest.profileSelectionSha256 !== (profileBytes === null ? null : sha(profileBytes))) fail("SOURCE_FINGERPRINT_BINDING_MISMATCH");
  const profile = profileBytes === null ? undefined : json(Buffer.from(profileBytes), 2 * 1024 * 1024);
  const token = Object.freeze(Object.create(null)) as ExpectedSourceFingerprint;
  expected.set(token, { manifest: Object.freeze(manifest), profileCanonical: allocatorDigest(profile ?? null) });
  return token;
}
export function expectedSourceManifest(token: ExpectedSourceFingerprint): SourceFingerprint {
  const binding = expected.get(token); if (!binding) fail("SOURCE_FINGERPRINT_VERIFIED_BINDING_REQUIRED"); return binding.manifest;
}
type SourceTableFacts = { tableType: "BASE TABLE"; engine: "InnoDB" };
const sourceTables = Object.keys(accountImportTables);
const tablePlaceholders = sourceTables.map(() => "?").join(",");
async function sourceSchemas(c: Connection): Promise<Map<string, RowDataPacket[]>> {
  const [rows] = await c.query<RowDataPacket[]>(`SELECT TABLE_NAME AS tableName,COLUMN_NAME AS Field,COLUMN_TYPE AS Type FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (${tablePlaceholders}) ORDER BY TABLE_NAME,ORDINAL_POSITION`, sourceTables);
  const schemas = new Map<string, RowDataPacket[]>();
  for (const row of rows) { const schema = schemas.get(row.tableName) ?? []; schema.push(row); schemas.set(row.tableName, schema); }
  return schemas;
}
type RawTable = { table: string; facts: SourceTableFacts | null; present: boolean; columns: { name: string; type: string }[]; rows: { key: string; hash: string }[] };
/** Only actual raw source rows enter this accumulator. Target archives and profile
 * selection projections must never substitute for unselected raw profile rows.
 */
export class RawSourceFingerprint {
  readonly #tables = new Map<string, RawTable>();
  #verified = false;
  constructor(readonly maxRows: number) {
    if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 1000000) fail("SOURCE_FINGERPRINT_ROW_BOUND");
  }
  add(table: string, schema: readonly Record<string, unknown>[] | null, columns: readonly string[], rows: readonly Record<string, unknown>[]) {
    if (this.#verified || !Object.hasOwn(accountImportTables, table) || this.#tables.has(table) || rows.length > this.maxRows) fail("SOURCE_FINGERPRINT_TABLE_BOUND");
    const allowed = table === "user_info" ? [...accountImportTables[table], "avatar_id"] : accountImportTables[table];
    if (new Set(columns).size !== columns.length || columns.some(c => !allowed.includes(c))) fail("SOURCE_FINGERPRINT_COLUMNS_INVALID");
    if (schema === null && (rows.length || columns.length)) fail("SOURCE_FINGERPRINT_SCHEMA_INVALID");
    const selected = columns.map(name => {
      const matches = schema?.filter(c => c.Field === name) ?? [];
      if (matches.length !== 1 || typeof matches[0].Type !== "string") fail("SOURCE_FINGERPRINT_SCHEMA_INVALID");
      return { name, type: matches[0].Type as string };
    });
    if (schema && !migrationPrimaryKeys[table].every(k => columns.includes(k))) fail("SOURCE_FINGERPRINT_PRIMARY_KEY_REQUIRED");
    if (table === "user_info" && schema) { legacyProfileJsonTypeSelection(schema); assertProfileJsonValues(rows, true); }
    const keys = new Set<string>();
    const hashed = rows.map(row => {
      const key = migrationRowKey(table, row).keyHash;
      if (keys.has(key)) fail("SOURCE_FINGERPRINT_DUPLICATE_KEY"); keys.add(key);
      return { key, hash: migrationRowHash(row, columns) };
    }).sort((a, b) => a.key.localeCompare(b.key));
    this.#tables.set(table, { table, facts: null, present: schema !== null, columns: selected, rows: hashed });
  }
  /** All actual SELECTs have acquired transaction-duration MDL first. Recheck
   * existence/engine AND selected types from real metadata under those locks;
   * the initial batched COLUMNS read alone is never schema evidence.
   */
  async verifyTables(c: Connection): Promise<void> {
    if (this.#verified || this.#tables.size !== sourceTables.length) fail("SOURCE_FINGERPRINT_INCOMPLETE");
    const [rows] = await c.query<RowDataPacket[]>(`SELECT t.TABLE_NAME AS tableName,t.TABLE_TYPE AS tableType,t.ENGINE AS engine,c.COLUMN_NAME AS columnName,c.COLUMN_TYPE AS columnType FROM information_schema.TABLES t LEFT JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA=t.TABLE_SCHEMA AND c.TABLE_NAME=t.TABLE_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME IN (${tablePlaceholders}) ORDER BY t.TABLE_NAME,c.ORDINAL_POSITION`, sourceTables);
    for (const table of this.#tables.values()) {
      const metadata = rows.filter(row => row.tableName === table.table);
      if (!table.present) { if (metadata.length) fail("SOURCE_FINGERPRINT_SCHEMA_CHANGED_DURING_READ"); continue; }
      if (!metadata.length || metadata.some(row => row.tableType !== "BASE TABLE" || row.engine !== "InnoDB")) fail("SOURCE_FINGERPRINT_TRANSACTIONAL_TABLE_REQUIRED");
      const allowed = table.table === "user_info" ? [...accountImportTables[table.table], "avatar_id"] : accountImportTables[table.table];
      const actualColumns = allowed.flatMap(name => {
        const matches = metadata.filter(row => row.columnName === name);
        if (matches.length > 1 || (matches.length && typeof matches[0].columnType !== "string")) fail("SOURCE_FINGERPRINT_SCHEMA_CHANGED_DURING_READ");
        return matches.length ? [{ name, type: matches[0].columnType as string }] : [];
      });
      if (allocatorDigest(actualColumns) !== allocatorDigest(table.columns)) fail("SOURCE_FINGERPRINT_SCHEMA_CHANGED_DURING_READ");
      table.facts = { tableType: "BASE TABLE", engine: "InnoDB" };
    }
    this.#verified = true;
  }
  digests() {
    if (!this.#verified || this.#tables.size !== Object.keys(accountImportTables).length) fail("SOURCE_FINGERPRINT_INCOMPLETE");
    const tables = [...this.#tables.values()].sort((a, b) => a.table.localeCompare(b.table));
    return { schemaSha256: allocatorDigest(tables.map(({ table, present, facts, columns }) => ({ table, present, facts, columns }))), rowsSha256: allocatorDigest(tables.map(({ table, rows }) => ({ table, rows }))) };
  }
}
export async function assertActualSourceFingerprint(c: Connection, location: { name?: unknown; server_id?: unknown }, raw: RawSourceFingerprint, token: ExpectedSourceFingerprint, profileSelection?: ProfileSelectionManifest) {
  const binding = expected.get(token); if (!binding) fail("SOURCE_FINGERPRINT_VERIFIED_BINDING_REQUIRED");
  const m = binding.manifest;
  if (location.name !== m.database || location.server_id !== m.serverUuid || raw.maxRows !== m.maxRows || allocatorDigest(profileSelection ?? null) !== binding.profileCanonical) fail("SOURCE_FINGERPRINT_IDENTITY_MISMATCH");
  await raw.verifyTables(c);
  const hashes = raw.digests(), inventory = await readSourceAllocatorInventory(c);
  if (hashes.schemaSha256 !== m.schemaSha256 || hashes.rowsSha256 !== m.rowsSha256 || inventory.metadataSha256 !== m.allocatorMetadataSha256 || inventory.stateSha256 !== m.allocatorStateSha256) fail("SOURCE_FINGERPRINT_DRIFT");
}
/** Owns only its fresh read-only snapshot, never a caller transaction. */
export async function readActualSourceFingerprint(c: Connection, binding: { profileSelectionSha256: string | null; maxRows: number }): Promise<SourceFingerprint> {
  if (binding.profileSelectionSha256 !== null && !hash.safeParse(binding.profileSelectionSha256).success) fail("SOURCE_FINGERPRINT_BINDING_MISMATCH");
  const raw = new RawSourceFingerprint(binding.maxRows);
  await c.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
  const [mode] = await c.query<RowDataPacket[]>("SELECT @@autocommit AS enabled");
  if (Number(mode[0]?.enabled) !== 1) fail("SOURCE_FINGERPRINT_IDLE_CONNECTION_REQUIRED");
  await c.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  try {
    const [location] = await c.query<RowDataPacket[]>("SELECT DATABASE() AS name,@@server_uuid AS server_id");
    if (location.length !== 1 || location[0].name !== database || location[0].server_id !== serverUuid) fail("SOURCE_FINGERPRINT_IDENTITY_MISMATCH");
    const schemas = await sourceSchemas(c);
    for (const [table, allowed] of Object.entries(accountImportTables)) {
      const schema = schemas.get(table);
      if (!schema) {
        if (["user", "auth_item", "auth_assignment"].includes(table)) fail("SOURCE_FINGERPRINT_REQUIRED_TABLE_MISSING");
        raw.add(table, null, [], []); continue;
      }
      const columns = allowed.filter(name => schema.some(col => col.Field === name));
      if (table === "user_info" && schema.some(col => col.Field === "avatar_id")) columns.push("avatar_id");
      const type = table === "user_info" ? legacyProfileJsonTypeSelection(schema) : "";
      const [rows] = await c.query<RowDataPacket[]>(`SELECT ${columns.map(name => `\`${name}\``).join(",")}${type} FROM \`${table}\` LIMIT ${binding.maxRows + 1}`);
      raw.add(table, schema, columns, rows);
    }
    await raw.verifyTables(c);
    const inventory = await readSourceAllocatorInventory(c), [clock] = await c.query<RowDataPacket[]>("SELECT UTC_TIMESTAMP(3) AS now");
    if (!(clock[0]?.now instanceof Date)) fail("SOURCE_FINGERPRINT_CLOCK_REQUIRED");
    return sourceFingerprintSchema.parse({ version: 1, kind: "identity-account-source-fingerprint", database, serverUuid, ...binding, ...raw.digests(), allocatorMetadataSha256: inventory.metadataSha256, allocatorStateSha256: inventory.stateSha256, observedAt: clock[0].now.toISOString() });
  } finally { await c.rollback(); }
}
export function assertSameSourceFingerprint(a: SourceFingerprint, b: SourceFingerprint) {
  const { observedAt: _at, ...first } = a, { observedAt: _bt, ...second } = b;
  if (allocatorDigest(first) !== allocatorDigest(second)) fail("SOURCE_FINGERPRINT_DRIFT");
}
