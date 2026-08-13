import { describe, expect, it, vi } from "vitest";
import {
  ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS,
  ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256,
  openMysqlRepeatableReadSnapshot,
  type MysqlRepeatableReadSnapshotConnection
} from "../src/iam-organization-reconciliation/mysql-repeatable-read-snapshot.js";

const SET_REPEATABLE_READ = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
const START_READ_ONLY_SNAPSHOT = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY";
const DIRECTORY_STATEMENT_ID = "legacy-organization-directory-page/v3" as const;
const DIRECTORY_SQL = ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[DIRECTORY_STATEMENT_ID];
const SUBJECT_STATEMENT_ID = "legacy-subject-universe-page/v3" as const;
const SUBJECT_SQL = ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[SUBJECT_STATEMENT_ID];
const RBAC_EDGE_STATEMENT_ID = "legacy-rbac-edge-page/v1" as const;
const RBAC_EDGE_SQL =
  "SELECT parent, child FROM auth_item_child WHERE (CAST(parent AS BINARY) > CAST(? AS BINARY)) OR (CAST(parent AS BINARY) = CAST(? AS BINARY) AND CAST(child AS BINARY) > CAST(? AS BINARY)) ORDER BY CAST(parent AS BINARY) ASC, CAST(child AS BINARY) ASC LIMIT ?";

describe("organization reconciliation MySQL repeatable-read snapshot", () => {
  it("keeps setup, reads, commit, and release on one connection in strict order", async () => {
    const fake = fakeConnection({ rows: [{ id: 1 }] });
    const factory = vi.fn(async () => fake.connection);

    const session = await openMysqlRepeatableReadSnapshot(factory);
    const rows = await session.query<readonly { readonly id: number }[]>(
      DIRECTORY_STATEMENT_ID,
      [0, 100]
    );
    await session.close("completed");

    expect(rows).toEqual([{ id: 1 }]);
    expect(factory).toHaveBeenCalledTimes(1);
    expect(fake.queries).toEqual([
      [SET_REPEATABLE_READ, undefined],
      [START_READ_ONLY_SNAPSHOT, undefined],
      [DIRECTORY_SQL, [0, 100]],
      ["COMMIT", undefined]
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("rolls a failed collection back and releases exactly once", async () => {
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    await session.query(SUBJECT_STATEMENT_ID, [0, 100]);
    await session.close("failed");

    expect(fake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      SUBJECT_SQL,
      "ROLLBACK"
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("redacts connection-factory and transaction-setup failures", async () => {
    const factoryFailure = await openMysqlRepeatableReadSnapshot(async () => {
      throw new Error("mysql://private-user:private-password@private-host");
    }).catch((error: unknown) => error);
    expect(factoryFailure).toEqual(new Error("Opening the read-only MySQL snapshot failed."));
    expect(JSON.stringify(factoryFailure)).not.toContain("private-password");

    const fake = fakeConnection({ failSql: START_READ_ONLY_SNAPSHOT, secret: "private-setup-token" });
    const setupFailure = await openMysqlRepeatableReadSnapshot(async () => fake.connection)
      .catch((error: unknown) => error);
    expect(setupFailure).toEqual(new Error("Opening the read-only MySQL snapshot failed."));
    expect(JSON.stringify(setupFailure)).not.toContain("private-setup-token");
    expect(fake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      "ROLLBACK"
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("redacts read failures and still permits an explicit failed close", async () => {
    const fake = fakeConnection({ failSql: DIRECTORY_SQL, secret: "private-query-token" });
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    const failure = await session.query(DIRECTORY_STATEMENT_ID, [0, 100]).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("Reading from the read-only MySQL snapshot failed."));
    expect(JSON.stringify(failure)).not.toContain("private-query-token");
    await session.close("failed");

    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("rolls back and rejects a completed close after any read outcome is unknown", async () => {
    const fake = fakeConnection({ failSql: DIRECTORY_SQL, secret: "private-query-token" });
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    await session.query(DIRECTORY_STATEMENT_ID, [0, 100]).catch(() => undefined);
    const closeFailure = await session.close("completed").catch((error: unknown) => error);

    expect(closeFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(fake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      DIRECTORY_SQL,
      "ROLLBACK"
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it.each([
    "SELECT SLEEP(10)",
    "SELECT LOAD_FILE('/private/path')",
    "SELECT dangerous_udf(?)",
    "SELECT * FROM organization FOR UPDATE",
    "SHOW CREATE TABLE organization"
  ])("rejects arbitrary SQL text before it reaches the connection: %s", async (sql) => {
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    const failure = await session.query(sql as never, [] as never).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("The MySQL snapshot query is not an approved read-only statement."));
    expect(fake.queries).toHaveLength(2);

    const closeFailure = await session.close("completed").catch((error: unknown) => error);
    expect(closeFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("executes only reviewed statement IDs and exposes a stable catalog digest", async () => {
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    await session.query(DIRECTORY_STATEMENT_ID, [0, 100]);
    await session.query(SUBJECT_STATEMENT_ID, [0, 100]);
    await session.close("completed");

    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENT_CATALOG_SHA256).toMatch(/^[a-f0-9]{64}$/);
    expect(fake.queries).toHaveLength(5);
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("enumerates only Legacy RBAC role items and pins shadow ownership", () => {
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["legacy-role-assignment-page/v3"])
      .toContain("INNER JOIN auth_item AS ai ON ai.name = aa.item_name AND ai.type = 1");
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-membership-shadow-page/v3"])
      .toContain("source = 'legacy-shadow' AND status = 'shadow'");
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-role-shadow-page/v3"])
      .toContain("source = 'legacy-shadow' AND status = 'shadow'");
  });

  it("excludes inactive Identity-only tombstones from both reconciliation subject snapshots", () => {
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-subject-universe-page/v3"])
      .toContain("source = 'legacy-shadow' AND status = 'active'");
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-iam-subject-assignment-snapshot-page/v1"])
      .toContain("iu.source = 'legacy-shadow' AND iu.status = 'active'");
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-subject-universe-page/v3"])
      .not.toContain("'inactive'");
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS["identity-iam-subject-assignment-snapshot-page/v1"])
      .not.toContain("'inactive'");
  });

  it("pins the Legacy RBAC edge statement to binary keyset ordering and exact cursor parameters", async () => {
    expect(ORGANIZATION_RECONCILIATION_MYSQL_STATEMENTS[RBAC_EDGE_STATEMENT_ID]).toBe(RBAC_EDGE_SQL);
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    await session.query(RBAC_EDGE_STATEMENT_ID, ["", "", "", 100]);
    await session.query(RBAC_EDGE_STATEMENT_ID, ["parent", "parent", "child", 100]);
    await session.close("completed");

    expect(fake.queries.slice(2)).toEqual([
      [RBAC_EDGE_SQL, ["", "", "", 100]],
      [RBAC_EDGE_SQL, ["parent", "parent", "child", 100]],
      ["COMMIT", undefined]
    ]);
  });

  it("pins every Develop IAM statement to one exact policy checksum and read-only binary keysets", async () => {
    const checksum = ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM;
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);
    await session.query("identity-iam-policy-version-page/v1", [checksum, "", 100]);
    await session.query("identity-iam-role-page/v1", [checksum, "", 100]);
    await session.query("identity-iam-permission-page/v1", [checksum, "", 100]);
    await session.query("identity-iam-item-relation-page/v1", [checksum, "", "", "", 100]);
    await session.query("identity-iam-subject-assignment-page/v1", [
      checksum, 0, 0, "", 0, "", "", 100
    ]);
    await session.query("identity-iam-subject-assignment-snapshot-page/v1", [
      checksum, checksum, checksum, 0, 0, "", 100
    ]);
    await session.close("completed");
    expect(fake.queries.slice(2, -1).every(([statement]) => statement.startsWith("SELECT"))).toBe(true);
    expect(fake.queries.slice(2, -1).every(([statement]) => statement.includes("legacy-import-candidate"))).toBe(true);
    expect(fake.queries.at(-1)?.[0]).toBe("COMMIT");
  });

  it.each([
    [DIRECTORY_STATEMENT_ID, [0]],
    [DIRECTORY_STATEMENT_ID, [0, 0]],
    [DIRECTORY_STATEMENT_ID, [0, 5_001]],
    ["legacy-membership-page/v3", [1, 2, 0, 100]],
    [RBAC_EDGE_STATEMENT_ID, ["parent", "different-parent", "child", 100]],
    [RBAC_EDGE_STATEMENT_ID, ["parent", "parent", null, 100]],
    [RBAC_EDGE_STATEMENT_ID, ["p".repeat(65), "p".repeat(65), "child", 100]],
    [RBAC_EDGE_STATEMENT_ID, ["parent", "parent", "child"]],
    ["identity-membership-candidate-page/v3", [1, 1, 2, 1, 3, "user-a", 1, 2, "user-a", "org-a", 100]],
    ["identity-iam-policy-version-page/v1", ["0".repeat(64), "", 100]],
    ["identity-iam-item-relation-page/v1", [ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM, "left", "right", "child", 100]],
    ["identity-iam-subject-assignment-snapshot-page/v1", [ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM, ORGANIZATION_RECONCILIATION_DEVELOP_IAM_POLICY_CHECKSUM, "0".repeat(64), 0, 0, "", 100]],
    [DIRECTORY_STATEMENT_ID, [null, 100]],
    [DIRECTORY_STATEMENT_ID, [{ toSqlString: () => "SLEEP(10)" }, 100]],
    [DIRECTORY_STATEMENT_ID, [Number.NaN, 100]]
  ] as const)("rejects invalid parameters before executing %s", async (statementId, parameters) => {
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    const failure = await session.query(statementId, parameters as never).catch((error: unknown) => error);
    expect(failure).toEqual(new Error("The MySQL snapshot query is not an approved read-only statement."));
    expect(fake.queries).toHaveLength(2);
    const closeFailure = await session.close("completed").catch((error: unknown) => error);
    expect(closeFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(fake.queries.at(-1)?.[0]).toBe("ROLLBACK");
  });

  it("makes close idempotent and rejects queries as soon as close starts", async () => {
    const fake = fakeConnection();
    const session = await openMysqlRepeatableReadSnapshot(async () => fake.connection);

    const firstClose = session.close("completed");
    const secondClose = session.close("failed");
    const queryFailure = await session.query(DIRECTORY_STATEMENT_ID, [0, 100])
      .catch((error: unknown) => error);
    await Promise.all([firstClose, secondClose]);

    expect(queryFailure).toEqual(new Error("The read-only MySQL snapshot session is closed."));
    expect(fake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      "COMMIT"
    ]);
    expect(fake.release).toHaveBeenCalledTimes(1);

    await session.close("completed");
    expect(fake.release).toHaveBeenCalledTimes(1);
  });

  it("serializes reads and waits for every accepted query before commit and release", async () => {
    const queries: string[] = [];
    let finishRead!: () => void;
    const readBarrier = new Promise<void>((resolve) => {
      finishRead = resolve;
    });
    const release = vi.fn();
    const connection: MysqlRepeatableReadSnapshotConnection = {
      async query(sql) {
        queries.push(sql);
        if (sql === DIRECTORY_SQL) await readBarrier;
        return [[], []];
      },
      release
    };
    const session = await openMysqlRepeatableReadSnapshot(async () => connection);

    const read = session.query(DIRECTORY_STATEMENT_ID, [0, 100]);
    await vi.waitFor(() => expect(queries).toContain(DIRECTORY_SQL));
    const close = session.close("completed");
    await Promise.resolve();
    expect(queries).not.toContain("COMMIT");
    expect(release).not.toHaveBeenCalled();

    finishRead();
    await Promise.all([read, close]);
    expect(queries).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      DIRECTORY_SQL,
      "COMMIT"
    ]);
    expect(release).toHaveBeenCalledTimes(1);
  });

  it("redacts commit, rollback, and release failures without retrying release", async () => {
    const commitFake = fakeConnection({ failSql: "COMMIT", secret: "private-commit-token" });
    const commitSession = await openMysqlRepeatableReadSnapshot(async () => commitFake.connection);
    const commitClose = commitSession.close("completed");
    const duplicateClose = commitSession.close("completed");
    const commitFailure = await commitClose.catch((error: unknown) => error);
    await duplicateClose.catch(() => undefined);

    expect(commitFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(JSON.stringify(commitFailure)).not.toContain("private-commit-token");
    expect(commitFake.queries.map(([sql]) => sql)).toEqual([
      SET_REPEATABLE_READ,
      START_READ_ONLY_SNAPSHOT,
      "COMMIT",
      "ROLLBACK"
    ]);
    expect(commitFake.release).toHaveBeenCalledTimes(1);

    const rollbackFake = fakeConnection({ failSql: "ROLLBACK", secret: "private-rollback-token" });
    const rollbackSession = await openMysqlRepeatableReadSnapshot(async () => rollbackFake.connection);
    const rollbackFailure = await rollbackSession.close("failed").catch((error: unknown) => error);
    expect(rollbackFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(JSON.stringify(rollbackFailure)).not.toContain("private-rollback-token");
    expect(rollbackFake.release).toHaveBeenCalledTimes(1);

    const releaseFake = fakeConnection({ failRelease: true, secret: "private-release-token" });
    const releaseSession = await openMysqlRepeatableReadSnapshot(async () => releaseFake.connection);
    const releaseFailure = await releaseSession.close("completed").catch((error: unknown) => error);
    expect(releaseFailure).toEqual(new Error("Closing the read-only MySQL snapshot failed."));
    expect(JSON.stringify(releaseFailure)).not.toContain("private-release-token");
    expect(releaseFake.release).toHaveBeenCalledTimes(1);
  });
});

function fakeConnection(options: {
  readonly rows?: unknown;
  readonly failSql?: string;
  readonly failRelease?: boolean;
  readonly secret?: string;
} = {}): {
  readonly connection: MysqlRepeatableReadSnapshotConnection;
  readonly queries: Array<readonly [string, readonly unknown[] | undefined]>;
  readonly release: ReturnType<typeof vi.fn>;
} {
  const queries: Array<readonly [string, readonly unknown[] | undefined]> = [];
  const release = vi.fn(() => {
    if (options.failRelease) throw new Error(options.secret ?? "private-release-error");
  });
  const connection: MysqlRepeatableReadSnapshotConnection = {
    async query(sql, parameters) {
      queries.push([sql, parameters]);
      if (sql === options.failSql) throw new Error(options.secret ?? "private-query-error");
      return [options.rows ?? [], []];
    },
    release
  };
  return { connection, queries, release };
}
