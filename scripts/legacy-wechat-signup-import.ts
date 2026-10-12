import { lstat,readFile } from "node:fs/promises";
import { importLegacyWechatSignupCredentials } from "../apps/identity-adapter/src/legacy-wechat-signup-import.js";
import { legacyWechatSignupManifestDigest,normalizeLegacyWechatSignupManifest } from "../apps/identity-adapter/src/legacy-wechat-signup-manifest.js";
import { connectLegacySessionImportTarget } from "../apps/identity-adapter/src/legacy-session-import.js";
async function main(){
  const args=process.argv.slice(2);
  if(args.length===1&&args[0]==="--help"){console.log("Usage: legacy-wechat-signup-import --file=<owner-only-manifest.json> [--inspect|--dry-run|--apply]. Apply requires NODE_ENV=staging and explicit IDENTITY_LEGACY_WECHAT_SIGNUP_CONFIG_FILE.");return;}
  if(args.filter(arg=>arg.startsWith("--file=")).length!==1||args.some(arg=>!arg.startsWith("--file=")&&!["--inspect","--dry-run","--apply"].includes(arg))||
    args.filter(arg=>["--inspect","--dry-run","--apply"].includes(arg)).length>1||new Set(args).size!==args.length)throw new Error();
  const filename=args.find(arg=>arg.startsWith("--file="))!.slice(7),metadata=await lstat(filename);
  if(!metadata.isFile()||metadata.size>16*1024*1024||(metadata.mode&0o077)!==0)throw new Error();
  const manifest=normalizeLegacyWechatSignupManifest(JSON.parse(await readFile(filename,"utf8")));
  if(args.includes("--inspect")){console.log(JSON.stringify({total:manifest.credentials.length,manifestSha256:legacyWechatSignupManifestDigest(manifest),notFinal:true}));return;}
  const target=await connectLegacySessionImportTarget();
  try{console.log(JSON.stringify(await importLegacyWechatSignupCredentials(target,manifest,{apply:args.includes("--apply")})));}finally{await target.end();}
}
main().catch(()=>{console.error("Offline legacy WeChat signup import failed; review exact provider evidence, explicit trust, staging authority and tombstones. Inputs and SQL are never logged.");process.exitCode=1;});
