import { createHash, randomBytes } from "node:crypto";
import type { Connection, ResultSetHeader, RowDataPacket } from "mysql2/promise";
import { assertMigrationStaging } from "./migration-state.js";
import { assertWechatBinarySchema } from "./identity-yii-wechat-import.js";
export { importReviewedYiiWechatBindings } from "./identity-yii-wechat-import.js";

/** One-time auth UUID/provider import. Source remains a consistent read-only snapshot. */
export async function importWechatIdentities(source:Connection,target:Connection,options:{importKey:string;apply?:boolean;maxRows?:number}) {
  if(source===target||!/^[A-Za-z0-9_.:-]{1,160}$/.test(options.importKey))throw new Error("Invalid WeChat identity import configuration");
  await assertWechatBinarySchema(target);
  const [names]=await source.query<RowDataPacket[]>("SELECT DATABASE() AS name");
  const [runs]=await target.execute<RowDataPacket[]>("SELECT source_database,row_counts FROM identity_wechat_import_runs WHERE import_key=?",[options.importKey]);
  if(runs[0]) {if(runs[0].source_database!==names[0]?.name)throw new Error("Import key belongs to another source");return {applied:false,replay:true,rowCounts:typeof runs[0].row_counts==="string"?JSON.parse(runs[0].row_counts):runs[0].row_counts};}
  const bound=Math.min(Math.max(options.maxRows??100000,1),100000);
  await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  try {
    const [users]=await source.query<RowDataPacket[]>(`SELECT id,primary_unionid,display_name,avatar_url,status,created_at,updated_at FROM auth_users ORDER BY id LIMIT ${bound+1}`);
    const [identities]=await source.query<RowDataPacket[]>(`SELECT id,user_id,provider,provider_app_id,openid,unionid,profile_json FROM auth_identities ORDER BY user_id,id LIMIT ${bound+1}`);
    if(users.length>bound||identities.length>bound)throw new Error("WeChat identity import exceeds reviewed bound");
    const userIds=new Set(users.map((user)=>String(user.id)));
    if(identities.some((identity)=>!userIds.has(String(identity.user_id))||!["wechat_official_account","wechat_website","wechat_mini_program"].includes(identity.provider)))throw new Error("Invalid provider binding in source");
    const rowCounts={auth_users:users.length,auth_identities:identities.length};
    if(!options.apply)return {applied:false,replay:false,rowCounts};
    await target.beginTransaction();
    try {
      await assertMigrationStaging(target);
      await target.execute("INSERT INTO identity_wechat_import_runs(import_key,source_database,row_counts,completed_at)VALUES(?,?,?,UTC_TIMESTAMP(3))",[options.importKey,names[0].name,JSON.stringify(rowCounts)]);
      // A single lock covers the complete batch until commit, preserving outbox cursor order.
      await target.execute("SELECT id FROM identity_event_clock WHERE id=1 FOR UPDATE");
      for(const old of users) {
        const related=identities.filter((identity)=>String(identity.user_id)===String(old.id));
        const [existing]=await target.execute<RowDataPacket[]>("SELECT user_id FROM identity_auth_subject_maps WHERE auth_user_id=? FOR UPDATE",[old.id]);
        const candidates=new Set<number>(existing.map((row)=>Number(row.user_id)));
        for(const identity of related) {
          const [known]=await target.execute<RowDataPacket[]>("SELECT user_id,union_id FROM identity_wechat_identities WHERE BINARY provider=BINARY ? AND BINARY provider_app_id=BINARY ? AND BINARY open_id=BINARY ? FOR UPDATE",[identity.provider,identity.provider_app_id,identity.openid]);
          const unionId=identity.unionid??old.primary_unionid??null;
          if(known[0]?.union_id!=null && unionId!=null && known[0].union_id!==unionId)throw new Error("Verified provider union ID conflicts with the reviewed binding");
          const [legacy]=await target.execute<RowDataPacket[]>("SELECT user_id,openid,unionid FROM wechat WHERE BINARY openid=BINARY ? OR (? IS NOT NULL AND BINARY unionid=BINARY ?) FOR UPDATE",[identity.openid,unionId,unionId]);
          if(!known.some((row)=>row.user_id!=null) && legacy.some((row)=>row.openid===identity.openid && row.user_id!=null && (unionId==null || row.unionid!==unionId)))throw new Error("Review and import the exact Yii application binding before importing this OAuth account");
          for(const row of known.some((row)=>row.user_id!=null)?known:legacy.filter((row)=>unionId!=null && row.unionid===unionId))if(row.user_id!=null)candidates.add(Number(row.user_id));
        }
        if(candidates.size>1)throw new Error("OAuth UUID and provider binding conflict; explicit reconciliation is required");
        let userId=candidates.size?[...candidates][0]:null;
        if(userId===null) {
          // No old account is discarded, including profiles without a completed provider binding.
          const [created]=await target.execute<ResultSetHeader>("INSERT INTO user(username,nickname,auth_key,status,created_at,updated_at)VALUES(?,?,?,?,?,?)",
            [`oauth_${createHash("sha256").update(String(old.id)).digest("hex").slice(0,40)}`,old.display_name??null,randomBytes(24).toString("base64url"),old.status==="active"?10:0,unixSeconds(old.created_at),unixSeconds(old.updated_at)]);
          userId=created.insertId;
          await target.execute("INSERT INTO user_info(user_id,info)VALUES(?,?)",[userId,JSON.stringify({wechatAvatarUrl:old.avatar_url??null})]);
          await target.execute("INSERT INTO auth_assignment(item_name,user_id,created_at)VALUES('user',?,?)",[String(userId),Math.floor(Date.now()/1000)]);
          await target.execute("INSERT INTO identity_subject_events(user_id,version)VALUES(?,?)",[userId,Date.now()]);
        } else {
          const [accounts]=await target.execute<RowDataPacket[]>("SELECT id FROM user WHERE id=? FOR UPDATE",[userId]);if(!accounts[0])throw new Error("Canonical account mapping points to a missing user");
        }
        await target.execute("INSERT INTO identity_auth_subject_maps(auth_user_id,user_id,status)VALUES(?,?,?) ON DUPLICATE KEY UPDATE auth_user_id=VALUES(auth_user_id)",[old.id,userId,old.status]);
        for(const identity of related) {
          const raw=typeof identity.profile_json==="string"?JSON.parse(identity.profile_json):identity.profile_json??{};
          await target.execute(`INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id,user_id,union_id,profile_json)
            VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),union_id=COALESCE(union_id,VALUES(union_id)),profile_json=COALESCE(profile_json,VALUES(profile_json))`,
            [identity.provider,identity.provider_app_id,identity.openid,userId,identity.unionid??old.primary_unionid??null,JSON.stringify({...raw,nickname:old.display_name,avatarUrl:old.avatar_url})]);
        }
      }
      await target.commit();return {applied:true,replay:false,rowCounts};
    }catch(error){await target.rollback();throw error;}
  }finally{await source.rollback();}
}
function unixSeconds(value:unknown) {const date=value instanceof Date?value:new Date(`${String(value).replace(/Z$/,"")}Z`);if(!Number.isFinite(date.getTime()))throw new Error("Invalid account timestamp in import");return Math.floor(date.getTime()/1000);}
