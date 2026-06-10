import { Injectable, OnModuleDestroy } from "@nestjs/common";
import mysql, { Pool, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface InvitationRecordStats {
  configured: boolean;
  totalRecords: number;
  byCode: Array<{
    inviteCode: string;
    recordCount: number;
    firstCreatedAt: number | null;
    lastCreatedAt: number | null;
  }>;
}

export interface InvitationRecordRow {
  id: number;
  invite_code: string;
  inviter_id: number;
  invitee_id: number;
  created_at: number;
  username: string | null;
  email: string | null;
}

@Injectable()
export class InvitationRecordRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;

  constructor() {
    this.pool = this.createPool();
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool?.end();
  }

  isConfigured(): boolean {
    return this.pool !== null;
  }

  async getStats(inviteCode?: string | null): Promise<InvitationRecordStats> {
    if (!this.pool) {
      return {
        configured: false,
        totalRecords: 0,
        byCode: []
      };
    }

    const where = inviteCode ? "WHERE invite_code = ?" : "";
    const params = inviteCode ? [inviteCode] : [];
    const [summaryRows] = await this.pool.execute<RowDataPacket[]>(`SELECT COUNT(*) AS totalRecords FROM invitation_record ${where}`, params);
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT invite_code AS inviteCode,
              COUNT(*) AS recordCount,
              MIN(created_at) AS firstCreatedAt,
              MAX(created_at) AS lastCreatedAt
         FROM invitation_record
         ${where}
        GROUP BY invite_code
        ORDER BY lastCreatedAt DESC
        LIMIT 500`,
      params
    );

    return {
      configured: true,
      totalRecords: Number(summaryRows[0]?.totalRecords ?? 0),
      byCode: rows.map((row) => ({
        inviteCode: String(row.inviteCode),
        recordCount: Number(row.recordCount),
        firstCreatedAt: row.firstCreatedAt === null || row.firstCreatedAt === undefined ? null : Number(row.firstCreatedAt),
        lastCreatedAt: row.lastCreatedAt === null || row.lastCreatedAt === undefined ? null : Number(row.lastCreatedAt)
      }))
    };
  }

  async listByInviteCode(inviteCode?: string | null): Promise<{ configured: boolean; rows: InvitationRecordRow[] }> {
    if (!this.pool) {
      return {
        configured: false,
        rows: []
      };
    }
    if (!inviteCode) {
      return {
        configured: true,
        rows: []
      };
    }

    const [rows] = await this.pool.execute<RowDataPacket[]>(
      `SELECT ir.id,
              ir.invite_code,
              ir.inviter_id,
              ir.invitee_id,
              ir.created_at,
              u.username,
              u.email
         FROM invitation_record ir
         INNER JOIN user u ON u.id = ir.invitee_id
        WHERE ir.invite_code = ?
        ORDER BY ir.created_at DESC`,
      [inviteCode]
    );

    return {
      configured: true,
      rows: rows.map((row) => ({
        id: Number(row.id),
        invite_code: String(row.invite_code),
        inviter_id: Number(row.inviter_id),
        invitee_id: Number(row.invitee_id),
        created_at: Number(row.created_at),
        username: row.username === null || row.username === undefined ? null : String(row.username),
        email: row.email === null || row.email === undefined ? null : String(row.email)
      }))
    };
  }

  private createPool(): Pool | null {
    const { legacyDb } = this.config;
    if (!legacyDb.host || !legacyDb.user) {
      return null;
    }

    return mysql.createPool({
      host: legacyDb.host,
      port: legacyDb.port,
      database: legacyDb.name,
      user: legacyDb.user,
      password: legacyDb.password,
      waitForConnections: true,
      connectionLimit: 3,
      namedPlaceholders: false
    });
  }
}
