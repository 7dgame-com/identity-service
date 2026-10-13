import type { PoolConnection, RowDataPacket } from "mysql2/promise";
export async function hasRefreshGraphSchema(c:PoolConnection):Promise<boolean>{
  const [r]=await c.query<RowDataPacket[]>("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('identity_legacy_refresh_graph_families','identity_legacy_refresh_graph_credentials','identity_legacy_refresh_graph_replays')");
  if(r.length===0)return false;if(r.length!==3)throw new Error("Legacy graph schema is incomplete.");return true;
}
/** Caller holds the account lock; shared family revocation includes every P/S. */
export async function revokeRefreshGraphFamily(c:PoolConnection,family:string){
  await c.execute("UPDATE identity_legacy_refresh_graph_families SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE family_key=?",[family]);
  await c.execute("UPDATE identity_legacy_refresh_graph_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE family_key=?",[family]);
  await c.execute(`UPDATE identity_refresh_sessions s JOIN identity_legacy_refresh_graph_families f ON f.native_session_id=s.session_id SET s.revoked_at=COALESCE(s.revoked_at,UTC_TIMESTAMP(3)),s.replaced_by_hash=NULL WHERE f.family_key=?`,[family]);
}
export async function revokeRefreshGraphUser(c:PoolConnection,uid:number){
  if(!await hasRefreshGraphSchema(c))return;
  await c.execute("UPDATE identity_legacy_refresh_graph_families SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE legacy_user_id=?",[uid]);
  await c.execute("UPDATE identity_legacy_refresh_graph_credentials SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP(3)) WHERE legacy_user_id=?",[uid]);
}
export async function revokeRefreshGraphSession(c:PoolConnection,sid:string){
  if(!await hasRefreshGraphSchema(c))return;const [r]=await c.execute<RowDataPacket[]>("SELECT family_key FROM identity_legacy_refresh_graph_families WHERE native_session_id=?",[sid]);for(const f of r)await revokeRefreshGraphFamily(c,String(f.family_key));
}
