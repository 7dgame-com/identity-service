import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { LegacyRedisInvitation } from "./invitation-redis.reader.js";

export interface IdentityInvitation {
  inviteCode: string;
  quota: number;
  remaining: number;
  expiresAt: number;
  creatorLegacyUserId: number | null;
  creatorName: string | null;
  note: string | null;
  legacyCreatedAt: number;
  status: string;
  source: string;
  importedAt: Date | null;
  lastSeenAt: Date | null;
}

export interface CreateIdentityInvitationInput {
  inviteCode: string;
  quota: number;
  remaining: number;
  expiresAt: number;
  creatorLegacyUserId: number;
  creatorName: string;
  note: string;
  legacyCreatedAt: number;
  source: string;
}

@Injectable()
export class InvitationIdentityRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  private schemaReady: Promise<void> | null = null;

  constructor() {
    this.pool = this.createPool();
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  isConfigured(): boolean {
    return this.pool !== null;
  }

  async findByCodes(codes: string[]): Promise<IdentityInvitation[]> {
    if (codes.length === 0) {
      return [];
    }

    const pool = this.requirePool();
    await this.ensureSchema();
    const placeholders = codes.map(() => "?").join(",");
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT invite_code AS inviteCode,
              quota,
              remaining,
              expires_at AS expiresAt,
              creator_legacy_user_id AS creatorLegacyUserId,
              creator_name AS creatorName,
              note,
              legacy_created_at AS legacyCreatedAt,
              status,
              source,
              imported_at AS importedAt,
              last_seen_at AS lastSeenAt
         FROM identity_invitations
        WHERE invite_code IN (${placeholders})`,
      codes
    );

    return rows.map(normalizeIdentityInvitation);
  }

  async listActive(): Promise<IdentityInvitation[]> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [rows] = await pool.execute<RowDataPacket[]>(
      `SELECT invite_code AS inviteCode,
              quota,
              remaining,
              expires_at AS expiresAt,
              creator_legacy_user_id AS creatorLegacyUserId,
              creator_name AS creatorName,
              note,
              legacy_created_at AS legacyCreatedAt,
              status,
              source,
              imported_at AS importedAt,
              last_seen_at AS lastSeenAt
         FROM identity_invitations
        WHERE deleted_at IS NULL
        ORDER BY legacy_created_at DESC, id DESC`
    );

    return rows.map(normalizeIdentityInvitation);
  }

  async create(input: CreateIdentityInvitationInput): Promise<IdentityInvitation> {
    const pool = this.requirePool();
    await this.ensureSchema();
    await pool.execute<ResultSetHeader>(
      `INSERT INTO identity_invitations
        (invite_code, quota, remaining, expires_at, creator_legacy_user_id, creator_name, note, legacy_created_at, status, source, imported_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        input.inviteCode,
        input.quota,
        input.remaining,
        input.expiresAt,
        input.creatorLegacyUserId,
        input.creatorName,
        input.note,
        input.legacyCreatedAt,
        statusFromFields(input.expiresAt, input.remaining),
        input.source,
        new Date(),
        new Date()
      ]
    );

    const created = (await this.findByCodes([input.inviteCode]))[0];
    if (!created) {
      throw new Error("identity invitation was not created");
    }

    return created;
  }

  async markDeleted(inviteCode: string): Promise<boolean> {
    const pool = this.requirePool();
    await this.ensureSchema();
    const [result] = await pool.execute<ResultSetHeader>(
      `UPDATE identity_invitations
          SET status = 'deleted',
              deleted_at = COALESCE(deleted_at, ?)
        WHERE invite_code = ?
          AND deleted_at IS NULL`,
      [new Date(), inviteCode]
    );

    return result.affectedRows > 0;
  }

  async upsertImported(invitations: LegacyRedisInvitation[]): Promise<number> {
    if (invitations.length === 0) {
      return 0;
    }

    const pool = this.requirePool();
    await this.ensureSchema();
    let affected = 0;
    for (const invitation of invitations) {
      if (!isImportable(invitation)) {
        continue;
      }
      const [result] = await pool.execute<ResultSetHeader>(
        `INSERT INTO identity_invitations
          (invite_code, quota, remaining, expires_at, creator_legacy_user_id, creator_name, note, legacy_created_at, status, source, imported_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'legacy-redis', ?, ?)
         ON DUPLICATE KEY UPDATE
          quota = VALUES(quota),
          remaining = VALUES(remaining),
          expires_at = VALUES(expires_at),
          creator_legacy_user_id = VALUES(creator_legacy_user_id),
          creator_name = VALUES(creator_name),
          note = VALUES(note),
          legacy_created_at = VALUES(legacy_created_at),
          status = VALUES(status),
          source = VALUES(source),
          last_seen_at = VALUES(last_seen_at)`,
        [
          invitation.code,
          invitation.quota,
          invitation.remaining,
          invitation.expiresAt,
          invitation.creatorId,
          invitation.creatorName,
          invitation.note,
          invitation.createdAt,
          statusFromInvitation(invitation),
          new Date(),
          new Date()
        ]
      );
      affected += result.affectedRows;
    }

    return affected;
  }

  async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.createSchema();
    }

    return this.schemaReady;
  }

  private async createSchema(): Promise<void> {
    const pool = this.requirePool();
    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_invitations (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        invite_code VARCHAR(64) NOT NULL,
        quota INT UNSIGNED NOT NULL,
        remaining INT NOT NULL,
        expires_at BIGINT NOT NULL,
        creator_legacy_user_id BIGINT NULL,
        creator_name VARCHAR(255) NULL,
        note VARCHAR(1024) NULL,
        legacy_created_at BIGINT NOT NULL,
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        source VARCHAR(64) NOT NULL DEFAULT 'legacy-redis',
        imported_at DATETIME(3) NULL,
        last_seen_at DATETIME(3) NULL,
        deleted_at DATETIME(3) NULL,
        metadata JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_identity_invitations_code (invite_code),
        KEY idx_identity_invitations_status_expires (status, expires_at),
        KEY idx_identity_invitations_creator (creator_legacy_user_id, legacy_created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS invitation_email_challenges (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        challenge_key VARCHAR(160) NOT NULL,
        invite_code VARCHAR(64) NOT NULL,
        email VARCHAR(255) NOT NULL,
        code_hash CHAR(64) NOT NULL,
        attempts INT NOT NULL DEFAULT 0,
        expires_at DATETIME(3) NOT NULL,
        locked_until DATETIME(3) NULL,
        consumed_at DATETIME(3) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY idx_invitation_email_challenges_key (challenge_key),
        KEY idx_invitation_email_challenges_email (email, created_at),
        KEY idx_invitation_email_challenges_code (invite_code, created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
  }

  private requirePool(): Pool {
    if (!this.pool) {
      throw new Error("identity database is not configured");
    }

    return this.pool;
  }

  private createPool(): Pool | null {
    const { identityDb } = this.config;
    if (!identityDb.host || !identityDb.user) {
      return null;
    }

    return mysql.createPool({
      host: identityDb.host,
      port: identityDb.port,
      database: identityDb.name,
      user: identityDb.user,
      password: identityDb.password,
      waitForConnections: true,
      connectionLimit: 5,
      namedPlaceholders: false
    });
  }
}

export function isImportable(invitation: LegacyRedisInvitation): invitation is LegacyRedisInvitation & {
  quota: number;
  remaining: number;
  expiresAt: number;
  createdAt: number;
} {
  return invitation.quota !== null && invitation.quota > 0 && invitation.remaining !== null && invitation.expiresAt !== null && invitation.createdAt !== null;
}

export function statusFromInvitation(invitation: LegacyRedisInvitation): string {
  return statusFromFields(invitation.expiresAt, invitation.remaining);
}

function statusFromFields(expiresAt: number | null, remaining: number | null): string {
  const now = Math.floor(Date.now() / 1000);
  if (expiresAt !== null && expiresAt <= now) {
    return "expired";
  }
  if (remaining !== null && remaining <= 0) {
    return "used_up";
  }

  return "active";
}

function normalizeIdentityInvitation(row: RowDataPacket): IdentityInvitation {
  return {
    inviteCode: String(row.inviteCode),
    quota: Number(row.quota),
    remaining: Number(row.remaining),
    expiresAt: Number(row.expiresAt),
    creatorLegacyUserId: row.creatorLegacyUserId === null || row.creatorLegacyUserId === undefined ? null : Number(row.creatorLegacyUserId),
    creatorName: row.creatorName ?? null,
    note: row.note ?? null,
    legacyCreatedAt: Number(row.legacyCreatedAt),
    status: String(row.status),
    source: String(row.source),
    importedAt: row.importedAt ? toDate(row.importedAt) : null,
    lastSeenAt: row.lastSeenAt ? toDate(row.lastSeenAt) : null
  };
}

function toDate(value: unknown): Date {
  return value instanceof Date ? value : new Date(String(value));
}
