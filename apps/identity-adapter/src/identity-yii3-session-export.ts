import { createHash } from "node:crypto";
import { z } from "zod";
import { yii3ExpirySchema, yii3SourceSchema, yii3RefreshLifetime, type Yii3SessionEvidence } from "./yii3-session-evidence.js";

const positive=z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const snapshotSchema=z.object({version:z.literal(1),source:yii3SourceSchema,capturedAtMs:positive,
  entries:z.array(z.object({key:z.string().min(1).max(255),value:z.union([z.string().max(2048),z.record(z.string(),z.unknown())]),
    expiry:yii3ExpirySchema}).strict()).max(100000)}).strict();
const deviceValue=z.object({version:z.literal(1),user_id:positive,auth_method:z.literal("device_sn"),device_sn_id:positive}).strict();

/** Offline-only conversion. Source code review is required; this never proves writers are drained. */
export function exportYii3RefreshSessions(input:unknown) {
  const parsed=snapshotSchema.safeParse(input);if(!parsed.success)throw new Error("Invalid reviewed Yii3 refresh snapshot.");
  const snapshot=parsed.data;
  const sessions:Record<string,unknown>[]=[],seen=new Set<string>();
  let deviceSessions=0,conservativeLifetimes=0,maxUncertaintyMs=0;
  for(const entry of snapshot.entries){
    const token=entry.key.slice(snapshot.source.keyPrefix.length);
    if(!entry.key.startsWith(snapshot.source.keyPrefix)||! /^(?:dsn_)?[a-f0-9]{64}$/.test(token)||![64,68].includes(token.length))throw new Error("Invalid Yii3 refresh key shape.");
    const sn=token.startsWith("dsn_");
    let userId:number,deviceSnId:number|undefined;
    if(sn){
      let raw:unknown=entry.value;
      if(typeof raw==="string"){try{raw=JSON.parse(raw);}catch{throw new Error("Invalid Yii3 device refresh value.");}}
      const value=deviceValue.safeParse(raw);if(!value.success)throw new Error("Invalid Yii3 device refresh value.");
      userId=value.data.user_id;deviceSnId=value.data.device_sn_id;deviceSessions++;
    }else{
      if(typeof entry.value!=="string"||! /^[1-9][0-9]*$/.test(entry.value)||entry.value!==String(Number(entry.value))||!Number.isSafeInteger(Number(entry.value)))throw new Error("Invalid Yii3 ordinary refresh value.");
      userId=Number(entry.value);
    }
    const evidence:Yii3SessionEvidence={source:snapshot.source,expiry:entry.expiry,capturedAtMs:snapshot.capturedAtMs,
      credentialKind:sn?"device_sn":"ordinary"};
    const lifetime=yii3RefreshLifetime(evidence);
    if(lifetime.uncertaintyMs){conservativeLifetimes++;maxUncertaintyMs=Math.max(maxUncertaintyMs,lifetime.uncertaintyMs);}
    const tokenHash=createHash("sha256").update(token).digest("hex");
    if(seen.has(tokenHash))throw new Error("Duplicate Yii3 refresh snapshot entry.");seen.add(tokenHash);
    sessions.push({keyEncoding:"sha256-hex",key:tokenHash,user_id:userId,session_id:`yii3:${tokenHash}`,
      created_at:new Date(lifetime.issuedAtMs).toISOString(),expires_at:new Date(lifetime.expiresAtMs).toISOString(),
      revoked_at:null,client:null,...(sn?{auth_method:"device_sn",device_sn_id:deviceSnId}:{}),yii3:evidence});
  }
  return {manifest:{version:1 as const,sessions},report:{total:sessions.length,deviceSessions,ordinarySessions:sessions.length-deviceSessions,
    conservativeLifetimes,maxUncertaintyMs,notFinal:true as const,sourceWrites:0,targetWrites:0}};
}
