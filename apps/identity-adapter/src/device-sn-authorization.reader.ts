import { ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";
import mysql, { type Pool, type RowDataPacket } from "mysql2/promise";
import { isDeviceSnUuid, throwDeviceSnFailure } from "./device-sn-source.js";
import { assertReadonlySql } from "./readonly-write.guard.js";

export interface DeviceSnDbConfig {
  host?: string;
  port: number;
  name?: string;
  user?: string;
  password?: string;
}

/** Business device ownership only. This connection never reads accounts or credentials. */
export class DeviceSnAuthorizationReader {
  private readonly pool: Pool | null;

  constructor(db: DeviceSnDbConfig) {
    this.pool = db.host?.trim() && db.name?.trim() && db.user?.trim()
      ? mysql.createPool({ host: db.host, port: db.port, database: db.name, user: db.user,
          password: db.password, connectionLimit: 3, waitForConnections: true,
          connectTimeout: 5000, namedPlaceholders: false })
      : null;
  }

  async close(): Promise<void> { await this.pool?.end(); }

  async assertAuthorized(deviceSnId: number, userId: number, requireEnabled: boolean): Promise<void> {
    if (![deviceSnId, userId].every((id) => Number.isSafeInteger(id) && id > 0)) {
      throw new UnauthorizedException({ code: "DEVICE_SN_SOURCE_INVALID", message: "Device authorization source is invalid." });
    }
    if (!this.pool) throw new ServiceUnavailableException({ code: "DEVICE_SN_VALIDATION_UNAVAILABLE", message: "Device authorization source is not configured." });
    try {
      const sql = `SELECT id, device_uuid AS deviceUuid FROM device_sn
        WHERE id = ? AND user_id = ? AND activated_at IS NOT NULL
          AND (? = 0 OR enabled = 1) LIMIT 1`;
      assertReadonlySql(sql);
      const [rows] = await this.pool.execute<RowDataPacket[]>(sql, [deviceSnId, userId, requireEnabled ? 1 : 0]);
      if (rows.length !== 1 || !isDeviceSnUuid(rows[0].deviceUuid)) {
        throw new UnauthorizedException({ code: "DEVICE_SN_UNAVAILABLE", message: "Device authorization is unavailable." });
      }
    } catch (error) { throwDeviceSnFailure(error); }
  }

  async readiness(): Promise<boolean> {
    if (!this.pool) return false;
    try {
      const sql = "SELECT id, user_id, device_uuid, enabled, activated_at FROM device_sn LIMIT 0";
      assertReadonlySql(sql);
      await this.pool.query(sql);
      return true;
    } catch { return false; }
  }
}
