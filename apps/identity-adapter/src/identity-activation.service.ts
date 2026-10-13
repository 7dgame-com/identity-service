import { Injectable, OnModuleDestroy, ServiceUnavailableException } from "@nestjs/common";
import mysql, { type Pool } from "mysql2/promise";
import { loadConfig } from "./config.js";
import { immutableIdentityRevision, inspectExplicitActivationLocked, type ExplicitActivationStatus } from "./identity-activation.js";
import { readPrivateAllocatorInventory } from "./identity-allocator-state.js";

@Injectable()
export class IdentityActivationService implements OnModuleDestroy {
  private readonly config = loadConfig();
  private readonly pool: Pool | null;
  private warmed = false;
  private state: ExplicitActivationStatus = { authority: "staging", state: "sealed", receipt: null, allocatorManifestSha256: null };
  private refreshing: Promise<void> | null = null;
  readonly explicit = this.config.activationMode === "explicit";
  constructor() {
    if (this.explicit && this.config.dataSource !== "identity") throw new Error("Explicit activation requires the independent Identity data source");
    const db = this.config.identityDb;
    this.pool = this.explicit && db.host && db.user ? mysql.createPool({ host: db.host, port: db.port, database: db.name,
      user: db.user, password: db.password, connectionLimit: 2, timezone: "Z" }) : null;
  }
  async onModuleDestroy() { await this.pool?.end(); }
  /** Called after Native has validated the signing key. All operations are SELECT/transaction control. */
  async warm(): Promise<void> {
    if (!this.explicit) return;
    immutableIdentityRevision();
    if (!this.pool) throw new Error("Explicit activation requires the private Identity database");
    const c = await this.pool.getConnection();
    try {
      await c.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
      await c.beginTransaction();
      // The formal schema must already exist; a pending/missing allocator proof may be finalized later.
      await readPrivateAllocatorInventory(c);
      this.state = await inspectExplicitActivationLocked(c);
      this.warmed = true;
    } finally { try { await c.rollback(); } finally { c.release(); } }
  }
  private async refresh(): Promise<void> {
    if (this.state.state === "active" || !this.warmed || !this.pool) return;
    if (!this.refreshing) {
      this.refreshing = (async () => {
        const c = await this.pool!.getConnection();
        try {
          await c.query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED");
          await c.beginTransaction();
          // A singleton promise prevents concurrent first requests from opening the gate independently.
          this.state = await inspectExplicitActivationLocked(c);
        } finally { try { await c.rollback(); } finally { c.release(); } }
      })().finally(() => { this.refreshing = null; });
    }
    await this.refreshing;
  }
  async assertOpen(): Promise<void> {
    if (!this.explicit) return;
    try { await this.refresh(); }
    catch { throw new ServiceUnavailableException({ code: "IDENTITY_SEALED", message: "Identity is not active", ready: false }); }
    if (!this.warmed || this.state.state !== "active") throw new ServiceUnavailableException({ code: "IDENTITY_SEALED", message: "Identity is not active", ready: false });
  }
  async status() {
    await this.refresh();
    return this.peek();
  }
  peek() {
    return { mode: this.config.activationMode, state: this.state.state, warmed: this.warmed, ready: this.warmed && this.state.state === "active",
      authority: this.state.authority, allocatorManifestSha256: this.state.allocatorManifestSha256,
      revision: this.explicit ? immutableIdentityRevision() : undefined };
  }
}
