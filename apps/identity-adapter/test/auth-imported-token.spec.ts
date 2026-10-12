import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyImportedAuthAccessToken } from "../src/auth-imported-token-verifier.js";
let directory:string|undefined;
afterEach(()=>{vi.unstubAllEnvs();if(directory)rmSync(directory,{recursive:true,force:true});directory=undefined;});
describe("bounded imported OAuth access credentials",()=>{
  it("requires the original signature, issuer, client, scopes and both cutover deadlines",()=>{
    directory=mkdtempSync(join(tmpdir(),"identity-old-auth-"));
    const secret="old-hmac-key-with-at-least-32-bytes";
    const secretFile=join(directory,"old.key"),configFile=join(directory,"trust.json");writeFileSync(secretFile,secret);
    const now=Math.floor(Date.now()/1000);
    const trust={algorithm:"HS256",secretFile,issuer:"https://old-auth.test",audience:"bujiaban-web",allowedScopes:["openid","profile"],acceptUntil:new Date((now+300)*1000).toISOString(),issuedBefore:new Date((now+1)*1000).toISOString()};
    writeFileSync(configFile,JSON.stringify([trust]));vi.stubEnv("IDENTITY_AUTH_LEGACY_JWT_CONFIG_FILE",configFile);
    const claims={typ:"access",sub:"old-uuid",iss:"https://old-auth.test",aud:"bujiaban-web",scope:"openid profile",iat:now,exp:now+60};
    const sign=(payload:unknown,key=secret)=>{const input=[{alg:"HS256",typ:"JWT"},payload].map((value)=>Buffer.from(JSON.stringify(value)).toString("base64url")).join(".");return `${input}.${createHmac("sha256",key).update(input).digest("base64url")}`;};
    expect(verifyImportedAuthAccessToken(sign(claims))).toEqual({subject:"old-uuid",audience:"bujiaban-web",scopes:["openid","profile"],issuedAt:now});
    for(const mutation of [{iss:"https://untrusted.test"},{aud:"3dugc-web"},{scope:"openid admin"},{typ:"id"},{iat:now+2},{exp:now-1}])expect(()=>verifyImportedAuthAccessToken(sign({...claims,...mutation}))).toThrow();
    expect(()=>verifyImportedAuthAccessToken(sign(claims,"wrong-key"))).toThrow();
    writeFileSync(configFile,JSON.stringify([{...trust,acceptUntil:new Date((now-1)*1000).toISOString()}]));expect(()=>verifyImportedAuthAccessToken(sign(claims))).toThrow();
  });
});
