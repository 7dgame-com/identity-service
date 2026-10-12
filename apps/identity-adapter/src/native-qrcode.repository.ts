import { Injectable, OnModuleDestroy, ServiceUnavailableException, UnauthorizedException, ConflictException, HttpException } from "@nestjs/common";
import mysql, { Pool, RowDataPacket } from "mysql2/promise";
import { loadConfig } from "./config.js";

export interface NativeLoginCode { userId: number; expiresAt: number; context?: Record<string, unknown> | null; }
export interface NativeWechatScene { expiresAt: number; providerAppId: string | null; openId: string | null; userId: number | null; profile: Record<string, unknown> | null; }

/** Private Identity state stores code digests and subjects, never refresh tokens. */
@Injectable()
export class NativeQrcodeRepository implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;

  constructor() {
    const db = this.config.identityDb;
    this.pool = this.config.dataSource === "identity" && db.host && db.user
      ? mysql.createPool({ host: db.host, port: db.port, database: db.name, user: db.user,
        password: db.password, connectionLimit: 5, timezone: "Z" }) : null;
  }
  async onModuleDestroy() { await this.pool?.end(); }
  private db(): Pool {
    if (!this.pool) throw new ServiceUnavailableException("Identity QR state is unavailable");
    return this.pool;
  }

  async issueLoginCode(userId: number, digest: string, issuedAt: number, expiresAt: number, context: {frontend_domain?: string} = {}): Promise<void> {
    const connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      const [users] = await connection.execute<RowDataPacket[]>("SELECT status FROM user WHERE id = ? FOR UPDATE", [userId]);
      if (Number(users[0]?.status) !== 10) throw new UnauthorizedException();
      const [counts] = await connection.execute<RowDataPacket[]>(
        "SELECT COUNT(*) AS total FROM identity_login_codes WHERE user_id = ? AND issued_at > ?", [userId, issuedAt - 60]);
      const configured = Number(process.env.LOGIN_CODE_ISSUE_LIMIT ?? 5);
      const limit = Number.isInteger(configured) && configured >= 2 && configured <= 20 ? configured : 5;
      if (Number(counts[0]?.total) >= limit) throw new HttpException({ code: "LOGIN_CODE_RATE_LIMITED", message: "登录码生成过于频繁" }, 429);
      await connection.execute("INSERT INTO identity_login_codes (code_hash,user_id,issued_at,expires_at,context_json) VALUES (?,?,?,?,?)",
        [digest, userId, issuedAt, expiresAt, JSON.stringify(context)]);
      await connection.commit();
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
  }

  async loginCode(digest: string): Promise<NativeLoginCode | null> {
    const [rows] = await this.db().execute<RowDataPacket[]>(
      "SELECT user_id,expires_at,context_json FROM identity_login_codes WHERE code_hash = ?", [digest]);
    if(!rows.length)return null;
    const context=rows[0].context_json;
    if(context!=null&&(typeof context!=="object"||Array.isArray(context)))throw new UnauthorizedException("Login code context is invalid.");
    return { userId: Number(rows[0].user_id), expiresAt: Number(rows[0].expires_at), context:context??null };
  }

  async createWechatScene(digest: string, expiresAt: number): Promise<void> {
    await this.db().execute("INSERT INTO identity_wechat_scenes (scene_hash,expires_at) VALUES (?,?)", [digest, expiresAt]);
  }

  async wechatScene(digest: string): Promise<NativeWechatScene | null> {
    const [rows] = await this.db().execute<RowDataPacket[]>(
      "SELECT expires_at,provider_app_id,open_id,user_id,profile_json FROM identity_wechat_scenes WHERE scene_hash = ?", [digest]);
    if (!rows.length) return null;
    const profile = typeof rows[0].profile_json === "string" ? JSON.parse(rows[0].profile_json) : rows[0].profile_json;
    return { expiresAt: Number(rows[0].expires_at), providerAppId: rows[0].provider_app_id,
      openId: rows[0].open_id, userId: rows[0].user_id == null ? null : Number(rows[0].user_id), profile: profile ?? null };
  }

  async hasActiveRegistration(digest: string, now: number): Promise<boolean> {
    const [rows] = await this.db().execute<RowDataPacket[]>(
      "SELECT scene_hash FROM identity_wechat_scenes WHERE signup_token_hash = ? AND expires_at > ? AND open_id IS NOT NULL LIMIT 1", [digest, now]);
    return rows.length > 0;
  }

  async confirmWechatScene(digest: string, providerAppId: string, openId: string, userId: number | null, signupTokenHash: string | null,
    profile: Record<string, unknown>, now: number): Promise<void> {
    const connection = await this.db().getConnection();
    try {
      await connection.beginTransaction();
      const [rows] = await connection.execute<RowDataPacket[]>(
        "SELECT expires_at,provider_app_id,open_id FROM identity_wechat_scenes WHERE scene_hash = ? FOR UPDATE", [digest]);
      if (!rows.length || Number(rows[0].expires_at) <= now) throw new UnauthorizedException("扫码凭据已过期");
      if (rows[0].open_id && (rows[0].open_id !== openId || rows[0].provider_app_id !== providerAppId)) {
        throw new ConflictException("扫码凭据已经绑定其他微信账号");
      }
      await connection.execute(
        "UPDATE identity_wechat_scenes SET provider_app_id = ?,open_id = ?,user_id = ?,signup_token_hash = COALESCE(?,signup_token_hash),profile_json = ? WHERE scene_hash = ?",
        [providerAppId, openId, userId, signupTokenHash, JSON.stringify(profile), digest]);
      await connection.commit();
    } catch (error) { await connection.rollback(); throw error; }
    finally { connection.release(); }
  }
}
