import { assertAdmissionWriter } from "./identity-admission.js";
import { allocatorMutation } from "./identity-allocator-state.js";
import { randomBytes } from "node:crypto";
import type { Connection,RowDataPacket } from "mysql2/promise";
import { assertMigrationStaging } from "./migration-state.js";
import { assertLegacyWechatSignupTrust,canonicalSignupJson,normalizeLegacyWechatSignupManifest } from "./legacy-wechat-signup-manifest.js";

/** Offline, explicit reviewed hash-only import; never creates tables or infers an application. */
export async function importLegacyWechatSignupCredentials(target:Connection,payload:unknown,options:{apply?:boolean;environment?:string;now?:Date}={}) {
  assertAdmissionWriter();
  if(options.apply&&(options.environment??process.env.NODE_ENV)!=="staging")throw new Error("Legacy signup apply requires staging.");
  const manifest=normalizeLegacyWechatSignupManifest(payload), manifestHash=assertLegacyWechatSignupTrust(manifest), now=options.now??new Date();
  if(!Number.isFinite(now.getTime())||new Date(manifest.capturedAt)>now)throw new Error("Invalid legacy signup capture time.");
  const report={total:manifest.credentials.length,imported:0,wouldImport:0,existing:0,permanent:0,expired:0,sourceRevoked:0,applied:false,notFinal:true as const};
  await target.beginTransaction();
  try {
    if(options.apply){await assertMigrationStaging(target);}
    const lock=options.apply?" FOR UPDATE":"";
    for(const row of manifest.credentials){
      const evidence=canonicalSignupJson({source:manifest.source,capturedAt:manifest.capturedAt,credential:row});
      const [existing]=await target.execute<RowDataPacket[]>(`SELECT * FROM identity_legacy_wechat_signup_credentials
        WHERE credential_hash=? OR (source_database=? AND source_record_id=?) OR (provider=? AND provider_app_id=? AND open_id=?)${lock}`,
        [row.credentialHash,manifest.source.database,row.recordId,row.provider,row.providerAppId,row.openId]);
      if(existing.length){
        const saved=existing[0],stored=typeof saved.evidence_json==="string"?JSON.parse(saved.evidence_json):saved.evidence_json;
        if(existing.length!==1||saved.credential_hash!==row.credentialHash||saved.manifest_hash!==manifestHash||saved.source_database!==manifest.source.database||Number(saved.source_record_id)!==row.recordId||saved.source_revision!==manifest.source.revision||
          saved.provider!==row.provider||saved.provider_app_id!==row.providerAppId||saved.open_id!==row.openId||asTime(saved.expires_at)!==asTime(row.expiresAt)||asTime(saved.source_revoked_at)!==asTime(row.sourceRevokedAt)||canonicalSignupJson(stored)!==evidence)
          throw new Error("Legacy signup evidence conflicts with an existing tombstone.");
        report.existing++;continue;
      }
      for(const [table,column] of [["identity_refresh_sessions","refresh_token_hash"],["identity_legacy_refresh_credentials","credential_hash"],["identity_login_codes","code_hash"],["identity_wechat_scenes","scene_hash"]]){
        const [known]=await target.execute<RowDataPacket[]>(`SELECT ${column} FROM ${table} WHERE ${column}=?${lock}`,[row.credentialHash]);
        if(known.length)throw new Error("Legacy signup conflicts with another known credential classification.");
      }
      const [bindings]=await target.execute<RowDataPacket[]>(`SELECT provider,provider_app_id,open_id,user_id FROM identity_wechat_identities
        WHERE provider=? AND provider_app_id=? AND open_id=?${lock}`,[row.provider,row.providerAppId,row.openId]);
      if(bindings.some(binding=>binding.provider!==row.provider||binding.provider_app_id!==row.providerAppId||binding.open_id!==row.openId||binding.user_id!=null))
        throw new Error("Legacy signup exact provider identity is already owned or ambiguous.");
      const [wechat]=await target.execute<RowDataPacket[]>(`SELECT id,openid,user_id FROM wechat WHERE id=? OR openid=?${lock}`,[row.recordId,row.openId]);
      if(wechat.length>1||wechat.some(saved=>Number(saved.id)!==row.recordId||saved.openid!==row.openId||saved.user_id!=null))
        throw new Error("Legacy signup source row conflicts with a private compatibility identity.");
      if(row.expiresAt===null)report.permanent++;else if(new Date(row.expiresAt)<=now)report.expired++;
      if(row.sourceRevokedAt)report.sourceRevoked++;report.wouldImport++;
      if(!options.apply)continue;
      await allocatorMutation(target,()=>target.execute(`INSERT INTO identity_wechat_identities(provider,provider_app_id,open_id) VALUES (?,?,?) ON DUPLICATE KEY UPDATE open_id=open_id`,[row.provider,row.providerAppId,row.openId]));
      // Never copy the legacy bearer into compatibility storage. New scans may use their own random challenge.
      if(!wechat.length)await allocatorMutation(target,()=>target.execute("INSERT INTO wechat(id,openid,token,created_at,updated_at) VALUES (?,?,?,?,?)",
        [row.recordId,row.openId,randomBytes(32).toString("base64url"),row.createdAt?new Date(row.createdAt):null,row.updatedAt?new Date(row.updatedAt):null]));
      else await allocatorMutation(target,()=>target.execute("UPDATE wechat SET token=? WHERE id=?",[randomBytes(32).toString("base64url"),row.recordId]));
      await allocatorMutation(target,()=>target.execute(`INSERT INTO identity_legacy_wechat_signup_credentials
        (credential_hash,source_database,source_record_id,source_revision,manifest_hash,evidence_json,provider,provider_app_id,open_id,expires_at,source_revoked_at,revoked_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,[row.credentialHash,manifest.source.database,row.recordId,manifest.source.revision,manifestHash,evidence,row.provider,row.providerAppId,row.openId,
          row.expiresAt?new Date(row.expiresAt):null,row.sourceRevokedAt?new Date(row.sourceRevokedAt):null,row.sourceRevokedAt?new Date(row.sourceRevokedAt):null]));
      report.imported++;
    }
    if(options.apply){await target.commit();report.applied=true;}else await target.rollback();return report;
  }catch(error){await target.rollback();throw error;}
}

function asTime(value:unknown):number|null{return value==null?null:new Date(value as string|Date).getTime();}
