import { createHash } from "node:crypto";

const SET_REPEATABLE_READ = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const START_READ_ONLY_SNAPSHOT = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";
const COMMIT = "COMMIT";
const ROLLBACK = "ROLLBACK";

const OPEN_FAILURE = "Opening the read-only MySQL snapshot failed.";
const QUERY_FAILURE = "Reading from the read-only MySQL snapshot failed.";
const CLOSE_FAILURE = "Closing the read-only MySQL snapshot failed.";
const CLOSED_FAILURE = "The read-only MySQL snapshot session is closed.";
const SQL_POLICY_FAILURE = "The MySQL snapshot query is not an approved read-only statement.";

/** Develop-only reviewed IAM candidate pin. It is not a production trust root. */
export const ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM =
  "a5d8ad00b1a5775e8c4bf40745f3ba2b623b4a7aa1704075fc2519d5ba1da532" as const;

/**
 * Immutable statement catalog. Runtime callers select one reviewed ID and can
 * never provide SQL text, identifiers, functions, comments, or locking clauses.
 * Adding a statement is a source-reviewed protocol change.
 */
export const ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS = Object.freeze({
  "legacy-organization-directory-page/v3":
    "SELECT id, name, title, created_at, updated_at FROM organization WHERE id > ? ORDER BY id ASC LIMIT ?",
  "legacy-subject-universe-page/v3":
    "SELECT id, status FROM `user` WHERE id > ? ORDER BY id ASC LIMIT ?",
  "legacy-membership-page/v3":
    "SELECT user_id, organization_id FROM user_organization WHERE (user_id > ?) OR (user_id = ? AND organization_id > ?) ORDER BY user_id ASC, organization_id ASC LIMIT ?",
  "legacy-role-assignment-page/v3":
    "SELECT u.id AS user_id, aa.item_name FROM auth_assignment AS aa INNER JOIN `user` AS u ON aa.user_id = CAST(u.id AS CHAR) INNER JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type = 1 WHERE (u.id > ?) OR (u.id = ? AND CAST(aa.item_name AS BINARY) > CAST(? AS BINARY)) ORDER BY u.id ASC, CAST(aa.item_name AS BINARY) ASC LIMIT ?",
  "legacy-rbac-edge-page/v1":
    "SELECT parent, child FROM auth_item_child WHERE (CAST(parent AS BINARY) > CAST(? AS BINARY)) OR (CAST(parent AS BINARY) = CAST(? AS BINARY) AND CAST(child AS BINARY) > CAST(? AS BINARY)) ORDER BY CAST(parent AS BINARY) ASC, CAST(child AS BINARY) ASC LIMIT ?",
  "legacy-rbac-item-page/v1":
    "SELECT name, type, description, rule_name FROM auth_item WHERE type IN (1, 2) AND CAST(name AS BINARY) > CAST(? AS BINARY) ORDER BY CAST(name AS BINARY) ASC LIMIT ?",
  "legacy-rbac-assignment-page/v1":
    "SELECT u.id AS user_id, aa.item_name, ai.type FROM auth_assignment AS aa INNER JOIN `user` AS u ON aa.user_id = CAST(u.id AS CHAR) INNER JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type IN (1, 2) WHERE (u.id > ?) OR (u.id = ? AND CAST(aa.item_name AS BINARY) > CAST(? AS BINARY)) ORDER BY u.id ASC, CAST(aa.item_name AS BINARY) ASC LIMIT ?",
  "identity-subject-universe-page/v3":
    "SELECT legacy_user_id, status, source FROM identity_users WHERE legacy_user_id IS NOT NULL AND source = 'legacy-shadow' AND status IN ('active', 'inactive') AND legacy_user_id > ? ORDER BY legacy_user_id ASC LIMIT ?",
  "identity-organization-candidate-page/v3":
    "SELECT legacy_organization_id, identity_organization_id, name, title, source, candidate_status FROM identity_organizations_candidate WHERE source = 'legacy' AND candidate_status = 'candidate' AND legacy_organization_id > ? ORDER BY legacy_organization_id ASC LIMIT ?",
  "identity-organization-id-map-page/v3":
    "SELECT legacy_organization_id, identity_organization_id, source, mapping_status FROM identity_organization_id_map WHERE source = 'legacy' AND mapping_status = 'active' AND legacy_organization_id > ? ORDER BY legacy_organization_id ASC LIMIT ?",
  "identity-membership-shadow-page/v3":
    "SELECT legacy_user_id, organization_id, organization_role, source, status FROM identity_organization_memberships_shadow WHERE source = 'legacy-shadow' AND status = 'shadow' AND ((legacy_user_id > ?) OR (legacy_user_id = ? AND organization_id > ?)) ORDER BY legacy_user_id ASC, organization_id ASC LIMIT ?",
  "identity-membership-candidate-page/v3":
    "SELECT legacy_user_id, legacy_organization_id, identity_user_id, identity_organization_id, organization_role, source, candidate_status, operation_key FROM identity_organization_memberships_candidate WHERE source = 'legacy' AND candidate_status = 'candidate' AND (legacy_user_id, legacy_organization_id, CAST(identity_user_id AS BINARY), CAST(identity_organization_id AS BINARY), CAST(operation_key AS BINARY)) > (?, ?, CAST(? AS BINARY), CAST(? AS BINARY), CAST(? AS BINARY)) ORDER BY legacy_user_id ASC, legacy_organization_id ASC, CAST(identity_user_id AS BINARY) ASC, CAST(identity_organization_id AS BINARY) ASC, CAST(operation_key AS BINARY) ASC LIMIT ?",
  "identity-membership-candidate-snapshot-page/v1":
    "SELECT identity_user_id, legacy_user_id, operation_key, organization_count, source, candidate_status FROM identity_organization_membership_snapshots WHERE source = 'legacy' AND candidate_status = 'candidate' AND ((legacy_user_id > ?) OR (legacy_user_id = ? AND CAST(operation_key AS BINARY) > CAST(? AS BINARY))) ORDER BY legacy_user_id ASC, CAST(operation_key AS BINARY) ASC LIMIT ?",
  "identity-role-shadow-page/v3":
    "SELECT legacy_user_id, role_name, source, status FROM identity_role_assignments_shadow WHERE source = 'legacy-shadow' AND status = 'shadow' AND ((legacy_user_id > ?) OR (legacy_user_id = ? AND CAST(role_name AS BINARY) > CAST(? AS BINARY))) ORDER BY legacy_user_id ASC, CAST(role_name AS BINARY) ASC LIMIT ?",
  "identity-iam-policy-version-page/v1":
    "SELECT checksum, source, status, role_count, permission_count, relation_count FROM identity_iam_policy_versions WHERE checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND CAST(checksum AS BINARY) > CAST(? AS BINARY) ORDER BY CAST(checksum AS BINARY) ASC LIMIT ?",
  "identity-iam-role-page/v1":
    "SELECT policy_checksum, role_name, description, source, status FROM identity_iam_roles WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND CAST(role_name AS BINARY) > CAST(? AS BINARY) ORDER BY CAST(role_name AS BINARY) ASC LIMIT ?",
  "identity-iam-permission-page/v1":
    "SELECT policy_checksum, permission_name, description, source, status FROM identity_iam_permissions WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND CAST(permission_name AS BINARY) > CAST(? AS BINARY) ORDER BY CAST(permission_name AS BINARY) ASC LIMIT ?",
  "identity-iam-item-relation-page/v1":
    "SELECT policy_checksum, parent_name, parent_type, child_name, child_type, source, status FROM identity_iam_item_relations WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND ((CAST(parent_name AS BINARY) > CAST(? AS BINARY)) OR (CAST(parent_name AS BINARY) = CAST(? AS BINARY) AND CAST(child_name AS BINARY) > CAST(? AS BINARY))) ORDER BY CAST(parent_name AS BINARY) ASC, CAST(child_name AS BINARY) ASC LIMIT ?",
  "identity-iam-subject-assignment-page/v1":
    "SELECT identity_user_id, legacy_user_id, item_name, item_type, policy_checksum, source, status FROM identity_iam_subject_assignments WHERE policy_checksum = ? AND source = 'legacy-import-candidate' AND status = 'candidate' AND legacy_user_id IS NOT NULL AND ((legacy_user_id > ?) OR (legacy_user_id = ? AND CAST(identity_user_id AS BINARY) > CAST(? AS BINARY)) OR (legacy_user_id = ? AND CAST(identity_user_id AS BINARY) = CAST(? AS BINARY) AND CAST(item_name AS BINARY) > CAST(? AS BINARY))) ORDER BY legacy_user_id ASC, CAST(identity_user_id AS BINARY) ASC, CAST(item_name AS BINARY) ASC LIMIT ?",
  "identity-iam-subject-assignment-snapshot-page/v1":
    "SELECT iu.id AS identity_user_id, iu.legacy_user_id, ? AS policy_checksum, ? AS snapshot_key, COUNT(isa.id) AS assignment_count, 'legacy-import-candidate' AS source, 'candidate' AS status FROM identity_users AS iu LEFT JOIN identity_iam_subject_assignments AS isa ON isa.identity_user_id = iu.id AND isa.legacy_user_id = iu.legacy_user_id AND isa.policy_checksum = ? AND isa.source = 'legacy-import-candidate' AND isa.status = 'candidate' WHERE iu.source = 'legacy-shadow' AND iu.status IN ('active', 'inactive') AND iu.legacy_user_id IS NOT NULL AND ((iu.legacy_user_id > ?) OR (iu.legacy_user_id = ? AND CAST(iu.id AS BINARY) > CAST(? AS BINARY))) GROUP BY iu.id, iu.legacy_user_id ORDER BY iu.legacy_user_id ASC, CAST(iu.id AS BINARY) ASC LIMIT ?",
  "plugin-registry-page/v3":
    "SELECT id, enabled, access_scope, organization_name FROM plugins WHERE CAST(id AS BINARY) > CAST(? AS BINARY) ORDER BY CAST(id AS BINARY) ASC LIMIT ?"
} as const);

export type OrganizationReconciliationMysqlStatementId =
  keyof typeof ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS;

export const ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256 = createHash("sha256")
  .update("iam-organization-reconciliation:mysql-statement-catalog:v1\u001f", "utf8")
  .update(JSON.stringify(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS), "utf8")
  .digest("hex");

export interface MysqlRepeatableReadSnapshotConnection {
  query(sql: string, parameters?: readonly unknown[]): Promise<readonly [unknown, unknown]>;
  release(): void | Promise<void>;
}

export type MysqlRepeatableReadSnapshotConnectionFactory =
  () => Promise<MysqlRepeatableReadSnapshotConnection>;

export type MysqlRepeatableReadSnapshotOutcome = "completed" | "failed";

export interface MysqlRepeatableReadSnapshotSession {
  query<TRows = readonly unknown[]>(
    statementId: OrganizationReconciliationMysqlStatementId,
    parameters: readonly MysqlSnapshotParameter[]
  ): Promise<TRows>;
  close(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void>;
}

export type MysqlSnapshotParameter = null | boolean | number | bigint | string;

/**
 * Opens a read-only repeatable-read snapshot on one injected connection. This
 * primitive never creates a database client and never switches connections.
 */
export async function openMysqlRepeatableReadSnapshot(
  connectionFactory: MysqlRepeatableReadSnapshotConnectionFactory
): Promise<MysqlRepeatableReadSnapshotSession> {
  let connection: MysqlRepeatableReadSnapshotConnection | null = null;
  try {
    connection = await connectionFactory();
    assertConnection(connection);
    await connection.query(SET_REPEATABLE_READ);
    await connection.query(START_READ_ONLY_SNAPSHOT);
    return new RepeatableReadSnapshotSession(connection);
  } catch {
    if (connection !== null) {
      await rollbackQuietly(connection);
      await releaseQuietly(connection);
    }
    throw new Error(OPEN_FAILURE);
  }
}

class RepeatableReadSnapshotSession implements MysqlRepeatableReadSnapshotSession {
  private closePromise: Promise<void> | null = null;
  private operationTail: Promise<void> = Promise.resolve();
  private readFailed = false;

  constructor(private readonly connection: MysqlRepeatableReadSnapshotConnection) {}

  async query<TRows = readonly unknown[]>(
    statementId: OrganizationReconciliationMysqlStatementId,
    parameters: readonly MysqlSnapshotParameter[]
  ): Promise<TRows> {
    if (this.closePromise !== null) throw new Error(CLOSED_FAILURE);
    let sql: string;
    try {
      sql = resolveReviewedStatement(statementId, parameters);
    } catch {
      this.readFailed = true;
      throw new Error(SQL_POLICY_FAILURE);
    }
    const operation = this.operationTail.then(async () => {
      try {
        const result = await this.connection.query(sql, parameters);
        if (!Array.isArray(result) || result.length < 1) throw new Error("invalid result envelope");
        return result[0] as TRows;
      } catch {
        this.readFailed = true;
        throw new Error(QUERY_FAILURE);
      }
    });
    this.operationTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  close(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void> {
    if (this.closePromise !== null) return this.closePromise;
    this.closePromise = this.finishClose(outcome);
    return this.closePromise;
  }

  private async finishClose(outcome: MysqlRepeatableReadSnapshotOutcome): Promise<void> {
    let failed = false;
    const validOutcome = outcome === "completed" || outcome === "failed";
    try {
      await this.operationTail;
      if (outcome === "completed" && !this.readFailed) {
        try {
          await this.connection.query(COMMIT);
        } catch {
          failed = true;
          await rollbackQuietly(this.connection);
        }
      } else {
        try {
          await this.connection.query(ROLLBACK);
        } catch {
          failed = true;
        }
        if (outcome === "completed" && this.readFailed) failed = true;
      }
    } finally {
      try {
        await this.connection.release();
      } catch {
        failed = true;
      }
    }
    if (!validOutcome || failed) throw new Error(CLOSE_FAILURE);
  }
}

function assertConnection(
  connection: MysqlRepeatableReadSnapshotConnection | null
): asserts connection is MysqlRepeatableReadSnapshotConnection {
  if (
    connection === null ||
    typeof connection !== "object" ||
    typeof connection.query !== "function" ||
    typeof connection.release !== "function"
  ) {
    throw new Error("invalid connection");
  }
}

function resolveReviewedStatement(
  statementId: OrganizationReconciliationMysqlStatementId,
  parameters: readonly MysqlSnapshotParameter[]
): string {
  if (
    typeof statementId !== "string" ||
    !Object.prototype.hasOwnProperty.call(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS, statementId)
  ) {
    throw new Error(SQL_POLICY_FAILURE);
  }
  const sql = ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[statementId];
  assertReadOnlySql(sql);
  if (!Array.isArray(parameters)) throw new Error(SQL_POLICY_FAILURE);
  const placeholderCount = sql.match(/\?/g)?.length ?? 0;
  if (parameters.length !== placeholderCount) throw new Error(SQL_POLICY_FAILURE);
  const pageSize = parameters.at(-1);
  if (typeof pageSize !== "number" || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 5_000) {
    throw new Error(SQL_POLICY_FAILURE);
  }
  const cursorParameters = parameters.slice(0, -1);
  switch (statementId) {
    case "legacy-organization-directory-page/v3":
    case "legacy-subject-universe-page/v3":
    case "identity-subject-universe-page/v3":
    case "identity-organization-candidate-page/v3":
    case "identity-organization-id-map-page/v3":
      requireNonNegativeId(cursorParameters[0]);
      break;
    case "legacy-membership-page/v3":
    case "identity-membership-shadow-page/v3":
      requireRepeatedNonNegativeId(cursorParameters[0], cursorParameters[1]);
      requireNonNegativeId(cursorParameters[2]);
      break;
    case "legacy-role-assignment-page/v3":
    case "identity-role-shadow-page/v3":
      requireRepeatedNonNegativeId(cursorParameters[0], cursorParameters[1]);
      requireCanonicalCursor(cursorParameters[2]);
      break;
    case "legacy-rbac-edge-page/v1":
      requireRepeatedValues(
        [cursorParameters[0], cursorParameters[1]],
        (value) => requireCanonicalCursor(value, 64)
      );
      requireCanonicalCursor(cursorParameters[2], 64);
      break;
    case "legacy-rbac-item-page/v1":
      requireCanonicalCursor(cursorParameters[0], 255);
      break;
    case "legacy-rbac-assignment-page/v1":
      requireRepeatedNonNegativeId(cursorParameters[0], cursorParameters[1]);
      requireCanonicalCursor(cursorParameters[2], 255);
      break;
    case "identity-membership-candidate-page/v3":
      requireNonNegativeId(cursorParameters[0]);
      requireNonNegativeId(cursorParameters[1]);
      requireCanonicalCursor(cursorParameters[2], 128);
      requireCanonicalCursor(cursorParameters[3], 128);
      requireCanonicalCursor(cursorParameters[4], 160);
      break;
    case "identity-membership-candidate-snapshot-page/v1":
      requireRepeatedNonNegativeId(cursorParameters[0], cursorParameters[1]);
      requireCanonicalCursor(cursorParameters[2], 160);
      break;
    case "identity-iam-policy-version-page/v1":
    case "identity-iam-role-page/v1":
    case "identity-iam-permission-page/v1":
      requireDevelopPolicyChecksum(cursorParameters[0]);
      requireCanonicalCursor(cursorParameters[1], 255);
      break;
    case "identity-iam-item-relation-page/v1":
      requireDevelopPolicyChecksum(cursorParameters[0]);
      requireRepeatedValues(
        [cursorParameters[1], cursorParameters[2]],
        (value) => requireCanonicalCursor(value, 255)
      );
      requireCanonicalCursor(cursorParameters[3], 255);
      break;
    case "identity-iam-subject-assignment-page/v1":
      requireDevelopPolicyChecksum(cursorParameters[0]);
      requireRepeatedValues(
        [cursorParameters[1], cursorParameters[2], cursorParameters[4]],
        requireNonNegativeId
      );
      requireRepeatedValues(
        [cursorParameters[3], cursorParameters[5]],
        (value) => requireCanonicalCursor(value, 64)
      );
      requireCanonicalCursor(cursorParameters[6], 255);
      break;
    case "identity-iam-subject-assignment-snapshot-page/v1":
      requireDevelopPolicyChecksum(cursorParameters[0]);
      requireDevelopPolicyChecksum(cursorParameters[1]);
      requireDevelopPolicyChecksum(cursorParameters[2]);
      requireRepeatedNonNegativeId(cursorParameters[3], cursorParameters[4]);
      requireCanonicalCursor(cursorParameters[5], 64);
      break;
    case "plugin-registry-page/v3":
      requireCanonicalCursor(cursorParameters[0]);
      break;
    default:
      throw new Error(SQL_POLICY_FAILURE);
  }
  return sql;
}

function requireDevelopPolicyChecksum(value: MysqlSnapshotParameter | undefined): void {
  if (value !== ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM) {
    throw new Error(SQL_POLICY_FAILURE);
  }
}

function requireRepeatedNonNegativeId(left: MysqlSnapshotParameter | undefined, right: MysqlSnapshotParameter | undefined): void {
  requireRepeatedValues([left, right], requireNonNegativeId);
}

function requireRepeatedValues(
  values: readonly (MysqlSnapshotParameter | undefined)[],
  validate: (value: MysqlSnapshotParameter | undefined) => void
): void {
  if (values.length < 1) throw new Error(SQL_POLICY_FAILURE);
  for (const value of values) validate(value);
  const canonical = values.map(canonicalParameter);
  if (canonical.some((value) => value !== canonical[0])) throw new Error(SQL_POLICY_FAILURE);
}

function requireNonNegativeId(value: MysqlSnapshotParameter | undefined): void {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(SQL_POLICY_FAILURE);
    return;
  }
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error(SQL_POLICY_FAILURE);
    return;
  }
  if (typeof value === "string" && /^(?:0|[1-9]\d*)$/.test(value)) return;
  throw new Error(SQL_POLICY_FAILURE);
}

function requireCanonicalCursor(value: MysqlSnapshotParameter | undefined, maxLength = 2_048): void {
  if (
    typeof value !== "string" ||
    value.length > maxLength ||
    value.trim() !== value ||
    value.normalize("NFC") !== value ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    throw new Error(SQL_POLICY_FAILURE);
  }
}

function canonicalParameter(value: MysqlSnapshotParameter | undefined): string {
  return typeof value === "bigint" ? value.toString(10) : String(value);
}

function assertReadOnlySql(sql: string): void {
  if (typeof sql !== "string" || sql.length === 0 || sql.length > 100_000 || sql.includes("\0")) {
    throw new Error(SQL_POLICY_FAILURE);
  }

  const visibleSql = scanVisibleSql(sql);
  const statement = removeSingleTrailingSemicolon(visibleSql);
  const tokens = statement.toUpperCase().match(/[A-Z_]+/g) ?? [];
  const root = tokens[0];
  if (root !== "SELECT" && root !== "SHOW" && root !== "EXPLAIN" && root !== "WITH") {
    throw new Error(SQL_POLICY_FAILURE);
  }

  if (root !== "SHOW") {
    const forbiddenTokens = new Set([
      "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "UPSERT",
      "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME",
      "GRANT", "REVOKE", "CALL", "DO", "HANDLER", "LOAD", "IMPORT",
      "LOCK", "UNLOCK", "SET", "USE", "START", "BEGIN", "COMMIT",
      "ROLLBACK", "SAVEPOINT", "RELEASE", "KILL", "SHUTDOWN", "FLUSH",
      "RESET", "INSTALL", "UNINSTALL", "TEMPORARY", "OUTFILE", "DUMPFILE",
      "SHARE", "GET_LOCK", "RELEASE_LOCK", "IS_FREE_LOCK", "IS_USED_LOCK"
    ]);
    if (tokens.some((token) => forbiddenTokens.has(token)) || statement.includes(":=")) {
      throw new Error(SQL_POLICY_FAILURE);
    }
  }
}

/** Replaces quoted values/identifiers with spaces and rejects all comments. */
function scanVisibleSql(sql: string): string {
  let visible = "";
  let quote: "'" | '"' | "`" | null = null;

  for (let index = 0; index < sql.length; index += 1) {
    const character = sql[index]!;
    if (quote !== null) {
      visible += " ";
      if (character === "\\") {
        if (index + 1 < sql.length) {
          visible += " ";
          index += 1;
        }
      } else if (character === quote) {
        if (sql[index + 1] === quote) {
          visible += " ";
          index += 1;
        } else {
          quote = null;
        }
      }
      continue;
    }

    if (character === "'" || character === '"' || character === "`") {
      quote = character;
      visible += " ";
      continue;
    }
    if (character === "#" || (character === "/" && sql[index + 1] === "*")) {
      throw new Error(SQL_POLICY_FAILURE);
    }
    if (
      character === "-" &&
      sql[index + 1] === "-" &&
      (sql[index + 2] === undefined || /\s/u.test(sql[index + 2]!))
    ) {
      throw new Error(SQL_POLICY_FAILURE);
    }
    visible += character;
  }

  if (quote !== null) throw new Error(SQL_POLICY_FAILURE);
  return visible.trim();
}

function removeSingleTrailingSemicolon(sql: string): string {
  const firstSemicolon = sql.indexOf(";");
  if (firstSemicolon === -1) return requireStatement(sql);
  if (firstSemicolon !== sql.length - 1 || sql.indexOf(";", firstSemicolon + 1) !== -1) {
    throw new Error(SQL_POLICY_FAILURE);
  }
  return requireStatement(sql.slice(0, -1).trim());
}

function requireStatement(sql: string): string {
  if (sql.length === 0) throw new Error(SQL_POLICY_FAILURE);
  return sql;
}

async function rollbackQuietly(connection: MysqlRepeatableReadSnapshotConnection): Promise<void> {
  try {
    await connection.query(ROLLBACK);
  } catch {
    // Preserve the stage-specific public error without driver details.
  }
}

async function releaseQuietly(connection: MysqlRepeatableReadSnapshotConnection): Promise<void> {
  try {
    await connection.release();
  } catch {
    // Preserve the stage-specific public error without driver details.
  }
}
