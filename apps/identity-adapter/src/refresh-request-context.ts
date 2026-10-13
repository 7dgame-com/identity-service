import { BadRequestException } from "@nestjs/common";
import { createHash } from "node:crypto";
import type { RequestContext } from "./token-issuance.service.js";
/** Node HTTP headers are latin1 strings; PHP's opaque key hashes the wire bytes. */
export function refreshHeaderContext(header:unknown,request?:{rawHeaders?:string[]}):Pick<RequestContext,"idempotencyKeyBytes"> {
  if(request?.rawHeaders?.filter((v,i)=>i%2===0&&v.toLowerCase()==="idempotency-key").length!>1)throw new BadRequestException("Duplicate Idempotency-Key.");
  if(header===undefined)return {};
  if(typeof header!=="string"||[...header].some(c=>c.charCodeAt(0)>255))throw new BadRequestException("Invalid Idempotency-Key.");
  const bytes=Buffer.from(header,"latin1");validate(bytes);return {idempotencyKeyBytes:bytes};
}
function validate(bytes:Buffer){if(bytes.length<1||bytes.length>256||bytes.some(b=>b<32||b===127))throw new BadRequestException("Invalid Idempotency-Key.");}
/** Direct library callers use UTF8; HTTP callers provide exact validated bytes. */
export function refreshRequestHash(context:RequestContext):string|null {
  const bytes=context.idempotencyKeyBytes??(context.idempotencyKey===undefined?undefined:Buffer.from(context.idempotencyKey));
  if(bytes===undefined)return null;validate(bytes);return createHash("sha256").update(bytes).digest("hex");
}
