import { invalidateAllocatorReady } from "./identity-allocator-state.js";
import { createHash } from "node:crypto";
import type { Connection, RowDataPacket } from "mysql2/promise";
import { z } from "zod";
import { assertMigrationStaging } from "./migration-state.js";
import { enqueueSubjectEvent } from "./subject-events.js";

const manifestSchema=z.array(z.object({legacyId:z.number().int().positive(),providerSubject:z.string().min(1).max(255),providerAppId:z.string().min(1).max(191)}));
export type ReviewedAppleManifest=z.infer<typeof manifestSchema>;

/** The historical table has no audience. Never infer it from email, subject or environment. */
export async function importLegacyAppleIdentities(source:Connection,target:Connection,options:{importKey:string;manifest?:ReviewedAppleManifest;apply?:boolean}) {
  if(source===target||!/^[A-Za-z0-9_.:-]{1,160}$/.test(options.importKey))throw new Error("Invalid Apple import configuration");
  const [tables]=await source.query<RowDataPacket[]>("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='apple_id'");
  if(!tables.length)return {applied:false,replay:false,rowCount:0,subjects:[]};
  await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
  try {
    const [rows]=await source.query<RowDataPacket[]>("SELECT id,apple_id,email,first_name,last_name,user_id FROM apple_id ORDER BY id LIMIT 100001");
    if(rows.length>100000)throw new Error("Legacy Apple import exceeds reviewed bound");
    const subjects=rows.map(row=>({legacyId:Number(row.id),providerSubject:String(row.apple_id),userId:row.user_id==null?null:Number(row.user_id)}));
    if(!rows.length)return {applied:false,replay:false,rowCount:0,subjects};
    // A read-only inventory is useful even though the PHP AppleId model is absent.
    if(!options.apply&&!options.manifest)return {applied:false,replay:false,rowCount:rows.length,requiresReviewedAppManifest:true,subjects};
    if(!options.manifest)throw new Error("Apple import requires a reviewed exact app manifest; the legacy AppleId model and audience provenance are unavailable");
    const manifest=manifestSchema.parse(options.manifest);
    if(!manifest.length||rows.some(row=>!manifest.some(item=>item.legacyId===Number(row.id)&&item.providerSubject===row.apple_id))
      ||manifest.some(item=>!rows.some(row=>item.legacyId===Number(row.id)&&item.providerSubject===row.apple_id)))throw new Error("Every legacy Apple subject requires a reviewed exact app manifest; the legacy AppleId model and audience provenance are unavailable");
    const keys=manifest.map(item=>JSON.stringify([item.providerAppId,item.providerSubject]));if(new Set(keys).size!==keys.length)throw new Error("Duplicate Apple provider binding in manifest");
    const mappingHash=createHash("sha256").update(JSON.stringify([...manifest].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))))).digest("hex");
    const [location]=await source.query<RowDataPacket[]>("SELECT DATABASE() AS name");
    const [runs]=await target.execute<RowDataPacket[]>("SELECT source_database,mapping_hash,row_count FROM identity_apple_import_runs WHERE import_key=?",[options.importKey]);
    if(runs[0]) {
      if(runs[0].source_database!==location[0].name||runs[0].mapping_hash!==mappingHash)throw new Error("Apple import key belongs to a different source or app manifest");
      return {applied:false,replay:true,rowCount:Number(runs[0].row_count)};
    }
    if(!options.apply)return {applied:false,replay:false,rowCount:rows.length,providerBindings:manifest.length};
    await target.beginTransaction();
    try {
      await assertMigrationStaging(target);await invalidateAllocatorReady(target);
      const affectedUsers=new Set<number>();
      for(const item of manifest) {
        const row=rows.find(row=>Number(row.id)===item.legacyId)!;
        if(row.user_id!=null) {
          const userId=Number(row.user_id);if(!Number.isSafeInteger(userId)||userId<1)throw new Error("Invalid legacy Apple user binding");
          const [users]=await target.execute<RowDataPacket[]>("SELECT id FROM user WHERE id=? FOR UPDATE",[userId]);
          if(!users.length)throw new Error("Legacy Apple binding points to an account not present in Identity");affectedUsers.add(userId);
        }
        const [current]=await target.execute<RowDataPacket[]>("SELECT user_id FROM identity_apple_identities WHERE provider_app_id=? AND subject=? FOR UPDATE",[item.providerAppId,item.providerSubject]);
        if(current[0]?.user_id!=null&&Number(current[0].user_id)!==Number(row.user_id))throw new Error("Apple provider binding conflicts with an existing canonical account");
        await target.execute(`INSERT INTO identity_apple_identities(provider_app_id,subject,user_id,email,first_name,last_name)
          VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE user_id=COALESCE(user_id,VALUES(user_id)),email=COALESCE(email,VALUES(email)),
          first_name=COALESCE(first_name,VALUES(first_name)),last_name=COALESCE(last_name,VALUES(last_name))`,
          [item.providerAppId,item.providerSubject,row.user_id??null,row.email??null,row.first_name??null,row.last_name??null]);
      }
      for(const userId of [...affectedUsers].sort((a,b)=>a-b))await enqueueSubjectEvent(target as never,userId);
      await target.execute("INSERT INTO identity_apple_import_runs(import_key,source_database,mapping_hash,row_count)VALUES(?,?,?,?)",[options.importKey,location[0].name,mappingHash,rows.length]);
      await target.commit();return {applied:true,replay:false,rowCount:rows.length,providerBindings:manifest.length};
    }catch(error){await target.rollback();throw error;}
  }finally{await source.rollback();}
}
