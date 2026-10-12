import { createHash } from "node:crypto";
import type { Connection } from "mysql2/promise";
import { describe, expect, it, vi } from "vitest";
import {
  importLegacySessions,
  normalizeLegacySessionManifest,
} from "../src/legacy-session-import.js";

const session = (overrides: Record<string, unknown> = {}) => ({
  keyEncoding: "plain",
  key: "old-refresh-token",
  user_id: 24,
  session_id: "old-session-24",
  created_at: 1700000000.125,
  expires_at: 1700604800.125,
  revoked_at: null,
  client: null,
  ...overrides,
});
const manifest = (...sessions: unknown[]) => ({ version: 1, sessions });
function target() {
  const execute = vi.fn(async (sql: string) => [
    sql.startsWith("SELECT authority")
      ? [{ authority: "staging" }]
      : sql.startsWith("SELECT id FROM user")
        ? [{ id: 24 }]
        : [],
    [],
  ]);
  const connection = {
    beginTransaction: vi.fn(),
    commit: vi.fn(),
    rollback: vi.fn(),
    execute,
  };
  return { ...connection, connection: connection as unknown as Connection };
}

describe("legacy session manifest", () => {
  it("distinguishes a hex plaintext key from an already hashed key without guessing", () => {
    const key = "a".repeat(64);
    const [plain, hashed] = normalizeLegacySessionManifest(
      manifest(session({ key }), session({ keyEncoding: "sha256-hex", key })),
    );
    expect(plain.refreshHash).toBe(
      createHash("sha256").update(key).digest("hex"),
    );
    expect(hashed.refreshHash).toBe(key);
  });

  it("retains original times, actor, hashes and client scope without issuing credentials", () => {
    const row = normalizeLegacySessionManifest(
      manifest(
        session({
          revoked_at: 1700000100.5,
          ip: "127.0.0.1",
          user_agent_hash: "B".repeat(64),
          client: {
            client_id: "unity",
            scopes: ["openid", "profile"],
            legacy_subject: "24",
          },
        }),
      ),
    )[0];
    expect(row).toMatchObject({
      userId: 24,
      sessionId: "old-session-24",
      userAgentHash: "b".repeat(64),
      client: {
        client_id: "unity",
        scopes: ["openid", "profile"],
        legacy_subject: "24",
      },
    });
    expect(row.issuedAt.toISOString()).toBe("2023-11-14T22:13:20.125Z");
    expect(row.expiresAt.toISOString()).toBe("2023-11-21T22:13:20.125Z");
    expect(row.revokedAt?.toISOString()).toBe("2023-11-14T22:15:00.500Z");
    expect(row.ipHash).toBe(
      createHash("sha256").update("127.0.0.1").digest("hex"),
    );
    expect(row).not.toHaveProperty("key");
  });

  it.each([
    { keyEncoding: undefined },
    { keyEncoding: "sha256-hex", key: "not-a-hash" },
    { user_id: "24" },
    { user_id: Number.MAX_SAFE_INTEGER + 1 },
    { expires_at: 1600000000 },
    { revoked_at: 1 },
    { ip: "raw", ip_hash: "a".repeat(64) },
    { client: { client_id: "unity", scopes: ["openid", "openid"] } },
  ])(
    "rejects malformed entries without putting the input key into errors",
    (override) => {
      expect(() =>
        normalizeLegacySessionManifest(manifest(session(override))),
      ).toThrow("Invalid legacy session manifest entry 1.");
      try {
        normalizeLegacySessionManifest(manifest(session(override)));
      } catch (error) {
        expect(String(error)).not.toContain("old-refresh-token");
      }
    },
  );
});

describe("legacy session import safeguards", () => {
  it("requires staging before any apply database action", async () => {
    const db = target();
    await expect(
      importLegacySessions(db.connection, manifest(session()), {
        apply: true,
        environment: "production",
      }),
    ).rejects.toThrow("only be applied in staging");
    expect(db.beginTransaction).not.toHaveBeenCalled();
  });
  it("defaults to dry-run and rolls back without any INSERT", async () => {
    const db = target();
    const report = await importLegacySessions(
      db.connection,
      manifest(session(), session()),
    );
    expect(report).toMatchObject({
      applied: false,
      total: 2,
      unique: 1,
      duplicates: 1,
      imported: 0,
      wouldImport: 1,
    });
    expect(
      db.execute.mock.calls.every(([sql]) => !sql.startsWith("INSERT")),
    ).toBe(true);
    expect(db.rollback).toHaveBeenCalledOnce();
    expect(db.commit).not.toHaveBeenCalled();
  });
  it("rejects conflicting duplicate hashes before database work", async () => {
    const db = target();
    await expect(
      importLegacySessions(
        db.connection,
        manifest(session(), session({ user_id: 25 })),
      ),
    ).rejects.toThrow("Conflicting duplicate");
    expect(db.beginTransaction).not.toHaveBeenCalled();
  });
  it("requires the account to have been imported already", async () => {
    const db = target();
    db.execute.mockImplementation(async (sql: string) => [
      sql.startsWith("SELECT authority") ? [{ authority: "staging" }] : [],
      [],
    ]);
    await expect(
      importLegacySessions(db.connection, manifest(session()), {
        apply: true,
        environment: "staging",
      }),
    ).rejects.toThrow("missing identity account");
    expect(db.rollback).toHaveBeenCalledOnce();
    expect(db.commit).not.toHaveBeenCalled();
  });
  it("holds the persistent staging fence and rejects active authority even when staging is requested", async () => {
    const db = target();
    db.execute.mockResolvedValue([[{ authority: "identity" }], []]);
    await expect(
      importLegacySessions(db.connection, manifest(session()), {
        apply: true,
        environment: "staging",
      }),
    ).rejects.toThrow("already authoritative");
    expect(db.execute).toHaveBeenCalledOnce();
    expect(db.execute.mock.calls[0][0]).toContain("FOR UPDATE");
    expect(db.rollback).toHaveBeenCalledOnce();
    expect(db.commit).not.toHaveBeenCalled();
  });
});
