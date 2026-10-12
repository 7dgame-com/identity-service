import type { Connection, RowDataPacket } from "mysql2/promise";

type Dataset = { columns: readonly string[]; rows: readonly Record<string, unknown>[] };
export class AccountImportConstraintError extends Error {
  readonly code="ACCOUNT_TARGET_UNIQUE_CONFLICT";
  constructor(readonly table:string,readonly index:string,readonly groups:number){
    super(`Target unique constraint conflicts: ${table}.${index}; groups=${groups}`);
  }
}
const sourceTables = new Set(["user", "user_info", "auth_rule", "auth_item", "auth_item_child", "auth_assignment",
  "organization", "user_organization", "wechat", "invitation_record", "invitation"]);
const identifier = (value: string) => {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error("Unsupported account constraint identifier");
  return `\`${value}\``;
};

/** Read-only preflight uses the target's real collation, never a JS approximation. */
export async function assertAccountImportUniqueConstraints(source: Connection, target: Connection,
  datasets: ReadonlyMap<string, Dataset>, options: { checkExistingTarget?: boolean } = {}): Promise<void> {
  for (const [table, dataset] of datasets) {
    if (!sourceTables.has(table) || !dataset.rows.length) continue;
    const [indexes] = await target.query<RowDataPacket[]>(`SELECT INDEX_NAME,COLUMN_NAME,SEQ_IN_INDEX,SUB_PART
      FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND NON_UNIQUE=0
      ORDER BY INDEX_NAME,SEQ_IN_INDEX`, [table]);
    const [columns] = await target.query<RowDataPacket[]>(`SELECT COLUMN_NAME,DATA_TYPE,CHARACTER_SET_NAME,COLLATION_NAME
      FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?`, [table]);
    const schema = new Map(columns.map((column) => [String(column.COLUMN_NAME), column]));
    const groups = new Map<string, RowDataPacket[]>();
    for (const index of indexes) {
      const name = String(index.INDEX_NAME);
      groups.set(name, [...(groups.get(name) ?? []), index]);
    }
    for (const [name, fields] of groups) {
      const keys: string[] = [], notNull: string[] = [];
      for (const field of fields) {
        if (typeof field.COLUMN_NAME !== "string" || !dataset.columns.includes(field.COLUMN_NAME)) {
          throw new Error(`Unsupported target unique constraint: ${table}.${name}`);
        }
        const column = schema.get(field.COLUMN_NAME);
        if (!column) throw new Error("Target unique column is missing");
        const quoted = identifier(field.COLUMN_NAME);
        let expression = quoted;
        if (column.CHARACTER_SET_NAME != null) {
          const charset = String(column.CHARACTER_SET_NAME), collation = String(column.COLLATION_NAME);
          if (!/^[a-z0-9_]+$/.test(charset) || !/^[a-z0-9_]+$/.test(collation)) throw new Error("Unsupported target collation");
          expression = `CONVERT(${quoted} USING ${charset}) COLLATE ${collation}`;
        } else if (["tinyint", "smallint", "mediumint", "int", "bigint"].includes(String(column.DATA_TYPE))) {
          expression = `CAST(${quoted} AS SIGNED)`;
        }
        if (field.SUB_PART != null) {
          const prefix = Number(field.SUB_PART);
          if (!Number.isSafeInteger(prefix) || prefix < 1) throw new Error("Unsupported target index prefix");
          expression = `LEFT(${expression},${prefix})`;
        }
        keys.push(expression);
        notNull.push(`${quoted} IS NOT NULL`);
      }
      const values: unknown[] = [];
      // Legacy rows outside the explicitly selected canonical profile projection
      // are retained in the archive, rather than inserted into UNIQUE(user_id).
      let selection = "";
      if (table === "user_info") {
        const ids = dataset.rows.map((row) => row.id);
        selection = ` AND id IN (${ids.map(() => "?").join(",")})`;
        values.push(...ids);
      }
      if (name === "PRIMARY") {
        const [nulls] = await source.query<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM ${identifier(table)}
          WHERE NOT (${notNull.join(" AND ")})${selection}`, values);
        if (Number(nulls[0].total)) throw new Error(`Target primary key has null source values: ${table}.${name}`);
      }
      const [conflicts] = await source.query<RowDataPacket[]>(`SELECT COUNT(*) AS total FROM (
        SELECT 1 FROM ${identifier(table)} WHERE ${notNull.join(" AND ")}${selection}
        GROUP BY ${keys.join(",")} HAVING COUNT(*)>1) AS account_unique_conflicts`, values);
      if (Number(conflicts[0].total)) {
        throw new AccountImportConstraintError(table,name,Number(conflicts[0].total));
      }
      if (options.checkExistingTarget) {
        const names = fields.map(field=>String(field.COLUMN_NAME));
        const [existing] = await target.query<RowDataPacket[]>(`SELECT ${keys.map((key,index)=>`${key} AS ${identifier(names[index])}`).join(",")}
          FROM ${identifier(table)} WHERE ${notNull.join(" AND ")} LIMIT 100001`);
        if(existing.length>100000)throw new Error("Target unique preflight exceeds its row bound");
        for(const row of existing){
          const [matches] = await source.query<RowDataPacket[]>(`SELECT ${names.map(identifier).join(",")}
            FROM ${identifier(table)} WHERE ${keys.map(key=>`${key}=?`).join(" AND ")}${selection} LIMIT 2`,
            [...names.map(column=>row[column]),...values]);
          // Only the intentionally seeded roles may be updated, and their names
          // must match exactly: a collation alias must never rename a privilege.
          if(matches.length&&(table!=="auth_item"||name!=="PRIMARY"||matches[0].name!==row.name))
            throw new AccountImportConstraintError(table,name,1);
        }
      }
    }
  }
}
