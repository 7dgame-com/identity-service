import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { z } from "zod";

const digest=z.string().length(64).regex(/^[a-f0-9]{64}$/);
const date=z.string().refine(value=>{const d=new Date(value);return Number.isFinite(d.getTime())&&d.toISOString()===value&&d.getUTCFullYear()<=9999;});
const exact=z.string().min(1).max(191).refine(value=>value.trim()===value&&!/[\u0000-\u0020\u007f]/.test(value));
export const legacyWechatSignupManifestSchema=z.object({
  version:z.literal(1),
  source:z.object({storage:z.literal("yii2-mysql-wechat"),database:z.string().min(1).max(255),table:z.literal("wechat"),
    revision:z.string().length(40).regex(/^[a-f0-9]{40}$/),writersDrained:z.literal(true),ownerlessReviewed:z.literal(true),
    lifetimeReviewed:z.literal(true),providerAppReviewed:z.literal(true),proofSha256:digest}).strict(),
  capturedAt:date,
  credentials:z.array(z.object({recordId:z.number().int().positive().max(Number.MAX_SAFE_INTEGER),credentialHash:digest,
    provider:z.literal("wechat_official_account"),providerAppId:exact,openId:exact,userId:z.null(),createdAt:date.nullable(),updatedAt:date.nullable(),
    expiresAt:date.nullable(),expirySource:z.enum(["absent","expires_at"]),sourceRevokedAt:date.nullable(),
    providerProof:z.object({kind:z.literal("official-user-info"),providerAppId:exact,openId:exact,verifiedAt:date,evidenceSha256:digest}).strict()
  }).strict()).min(1).max(10000)
}).strict();
export type LegacyWechatSignupManifest=z.infer<typeof legacyWechatSignupManifestSchema>;
export function normalizeLegacyWechatSignupManifest(value:unknown):LegacyWechatSignupManifest {
  const parsed=legacyWechatSignupManifestSchema.safeParse(value);
  if(!parsed.success)throw new Error("Invalid reviewed legacy WeChat signup manifest.");
  const manifest=parsed.data, hashes=new Set<string>(), records=new Set<number>(), identities=new Set<string>();
  for(const row of manifest.credentials){
    const identity=JSON.stringify([row.provider,row.providerAppId,row.openId]);
    if(hashes.has(row.credentialHash)||records.has(row.recordId)||identities.has(identity))throw new Error("Duplicate legacy signup evidence.");
    hashes.add(row.credentialHash);records.add(row.recordId);identities.add(identity);
    if((row.expirySource==="absent")!==(row.expiresAt===null)||row.providerProof.providerAppId!==row.providerAppId||row.providerProof.openId!==row.openId||
      new Date(row.providerProof.verifiedAt)>new Date(manifest.capturedAt)||[row.createdAt,row.updatedAt].some(value=>value!==null&&new Date(value)>new Date(manifest.capturedAt)))
      throw new Error("Inconsistent legacy signup lifetime or exact provider evidence.");
  }
  return {...manifest,credentials:[...manifest.credentials].sort((a,b)=>a.recordId-b.recordId)};
}
export function canonicalSignupJson(value:unknown):string {
  const normalize=(v:unknown):unknown=>Array.isArray(v)?v.map(normalize):v&&typeof v==="object"?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b)).map(([k,item])=>[k,normalize(item)])):v;
  return JSON.stringify(normalize(value));
}
export function legacyWechatSignupManifestDigest(value:unknown):string {
  return createHash("sha256").update(canonicalSignupJson(normalizeLegacyWechatSignupManifest(value))).digest("hex");
}
export interface LegacyWechatSignupTrust {version:1;manifestSha256:string;providerAppId:string;}
/** Independent, default-off capability trust. No TTL is synthesized for the old bearer. */
export function loadLegacyWechatSignupTrust():LegacyWechatSignupTrust|null {
  const filename=process.env.IDENTITY_LEGACY_WECHAT_SIGNUP_CONFIG_FILE;if(!filename)return null;
  try {
    const metadata=lstatSync(filename);if(!metadata.isFile()||metadata.size>16384)throw new Error();
    const parsed=z.object({version:z.literal(1),manifestSha256:digest,providerAppId:exact}).strict().safeParse(JSON.parse(readFileSync(filename,"utf8")));
    if(!parsed.success)throw new Error();return parsed.data;
  }catch{throw new Error("Legacy WeChat signup trust is invalid.");}
}
export function assertLegacyWechatSignupTrust(manifest:LegacyWechatSignupManifest):string {
  const trust=loadLegacyWechatSignupTrust(), hash=legacyWechatSignupManifestDigest(manifest);
  if(!trust||trust.manifestSha256!==hash||manifest.credentials.some(row=>row.providerAppId!==trust.providerAppId))throw new Error("Legacy WeChat signup manifest is not explicitly trusted.");
  return hash;
}
