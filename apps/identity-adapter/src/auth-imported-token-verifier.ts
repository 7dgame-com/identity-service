import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

/** Only OAuth userinfo uses this bounded bridge; it grants no primary API permission. */
export function verifyImportedAuthAccessToken(token:string): {subject:string;audience:string;scopes:string[];issuedAt:number} {
  const file=process.env.IDENTITY_AUTH_LEGACY_JWT_CONFIG_FILE;
  if(!file)throw new Error("Legacy OAuth access trust is not configured");
  const entries:unknown=JSON.parse(readFileSync(file,"utf8"));if(!Array.isArray(entries))throw new Error("Invalid legacy OAuth trust configuration");
  const parts=token.split(".");if(parts.length!==3)throw new Error("Invalid legacy OAuth token");
  const header=JSON.parse(Buffer.from(parts[0],"base64url").toString());const payload=JSON.parse(Buffer.from(parts[1],"base64url").toString());
  const now=Math.floor(Date.now()/1000);
  if(header.alg!=="HS256" || payload.typ!=="access" || typeof payload.sub!=="string" || typeof payload.aud!=="string"
    || !Number.isSafeInteger(payload.exp) || payload.exp<=now || !Number.isSafeInteger(payload.iat) || payload.iat>now+10
    || (payload.nbf!==undefined && (!Number.isFinite(payload.nbf)||payload.nbf>now+10)))throw new Error("Invalid legacy OAuth claims");
  const scopes:string[]=typeof payload.scope==="string"?payload.scope.split(/\s+/).filter(Boolean):[];
  for(const entry of entries) {
    if(!entry || entry.algorithm!=="HS256" || typeof entry.secretFile!=="string" || typeof entry.issuer!=="string"
      || typeof entry.audience!=="string" || !Array.isArray(entry.allowedScopes))continue;
    const deadline=Date.parse(entry.acceptUntil)/1000,lastIssue=Date.parse(entry.issuedBefore)/1000;
    if(!Number.isFinite(deadline)||!Number.isFinite(lastIssue)||now>=deadline||payload.iat>lastIssue||payload.iss!==entry.issuer||payload.aud!==entry.audience
      || !scopes.every((scope)=>entry.allowedScopes.includes(scope)))continue;
    const expected=createHmac("sha256",readFileSync(entry.secretFile,"utf8").trim()).update(`${parts[0]}.${parts[1]}`).digest();
    const signature=Buffer.from(parts[2],"base64url");
    if(expected.length===signature.length&&timingSafeEqual(expected,signature))return {subject:payload.sub,audience:payload.aud,scopes,issuedAt:payload.iat};
  }
  throw new Error("Legacy OAuth access token is not trusted");
}
