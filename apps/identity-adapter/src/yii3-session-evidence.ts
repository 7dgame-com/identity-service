import { z } from "zod";

export const YII3_REFRESH_TTL_MS=2_592_000_000;
const milliseconds=z.number().int().positive().max(253402300799999);
export const yii3SourceSchema=z.object({
  application:z.literal("yii3-a1"),sourceRevision:z.string().length(40).regex(/^[a-f0-9]{40}$/),
  redisDatabase:z.literal(1),keyPrefix:z.literal("refresh_token:"),fixedTtlSeconds:z.literal(2592000),
  expiryPolicy:z.literal("setex-on-create-only"),namespaceWritersReviewed:z.literal(true),
}).strict();
export const yii3ExpirySchema=z.discriminatedUnion("kind",[
  z.object({kind:z.literal("pexpiretime"),expiresAtMs:milliseconds,observedAtMs:milliseconds}).strict(),
  z.object({kind:z.literal("time-pttl-bracket"),timeBeforeMs:milliseconds,
    pttlMs:z.number().int().min(0).max(YII3_REFRESH_TTL_MS),timeAfterMs:milliseconds}).strict(),
]);
export const yii3SessionEvidenceSchema=z.object({source:yii3SourceSchema,expiry:yii3ExpirySchema,
  capturedAtMs:milliseconds,credentialKind:z.enum(["ordinary","device_sn"])}).strict();
export type Yii3SessionEvidence=z.infer<typeof yii3SessionEvidenceSchema>;

/** A bracket's lower bound can shorten lifetime, but never extends it. */
export function yii3RefreshLifetime(evidence:Yii3SessionEvidence):{issuedAtMs:number;expiresAtMs:number;uncertaintyMs:number} {
  const parsed=yii3SessionEvidenceSchema.safeParse(evidence);if(!parsed.success)throw new Error("Invalid reviewed Yii3 expiry evidence.");
  const expiry=parsed.data.expiry;
  let expiresAtMs:number,observedAtMs:number,uncertaintyMs=0;
  if(expiry.kind==="pexpiretime"){
    expiresAtMs=expiry.expiresAtMs;observedAtMs=expiry.observedAtMs;
  }else{
    uncertaintyMs=expiry.timeAfterMs-expiry.timeBeforeMs;
    if(uncertaintyMs<0||uncertaintyMs>2000)throw new Error("Yii3 expiry observation is not a bounded ordered bracket.");
    expiresAtMs=expiry.timeBeforeMs+expiry.pttlMs;observedAtMs=expiry.timeAfterMs;
  }
  if(observedAtMs>evidence.capturedAtMs||evidence.capturedAtMs-observedAtMs>60000
    ||expiresAtMs-observedAtMs>YII3_REFRESH_TTL_MS||expiresAtMs-YII3_REFRESH_TTL_MS<0)
    throw new Error("Yii3 expiry evidence is outside the reviewed fixed lifetime.");
  return {issuedAtMs:expiresAtMs-YII3_REFRESH_TTL_MS,expiresAtMs,uncertaintyMs};
}
