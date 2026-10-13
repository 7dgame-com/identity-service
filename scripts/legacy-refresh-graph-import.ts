import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { importRefreshGraph } from "../apps/identity-adapter/src/legacy-refresh-graph-import.js";
import { connectLegacySessionImportTarget } from "../apps/identity-adapter/src/legacy-session-import.js";
import { graphEncryptionKey } from "../apps/identity-adapter/src/legacy-refresh-graph-crypto.js";
import { LegacyIdentityReader } from "../apps/identity-adapter/src/legacy-identity.reader.js";
async function protectedBytes(path:string,bound:number){const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);try{const s=await f.stat();if(!s.isFile()||(s.mode&0o077)!==0||s.size>bound)throw new Error();const b=await f.readFile();if(b.length!==s.size||b.length>bound)throw new Error();return b;}finally{await f.close();}}
async function main(){
 const args=process.argv.slice(2);if(args.length===1&&args[0]==="--help"){console.log("Usage: NODE_ENV=staging IDENTITY_DATA_SOURCE=identity legacy-refresh-graph-import --file=<0600-manifest> --accounts=<0600-current-SQL-snapshot> [--dry-run|--apply --reviewed-sha256=<exact-file-SHA>]\nRequires explicit source response key env for each captured protocol. No source/Redis connection or schema creation. Default dry-run.");return;}
 if(new Set(args).size!==args.length||args.some(a=>!['--dry-run','--apply'].includes(a)&&!/^--(file|accounts|reviewed-sha256)=.+$/.test(a))||args.includes('--dry-run')&&args.includes('--apply'))throw new Error();
 const get=(k:string)=>{const v=args.filter(a=>a.startsWith(`--${k}=`));if(v.length!==1)throw new Error();return v[0].slice(k.length+3);};
 const manifest=await protectedBytes(get('file'),64*1024*1024),accounts=await protectedBytes(get('accounts'),32*1024*1024);
 const protocol=JSON.parse(manifest.toString()).protocol;
 const sourceKey=protocol==='yii3'?process.env.IDENTITY_LEGACY_YII3_RESPONSE_KEY:undefined;
 const sourceKeys=protocol==='ar'?Object.fromEntries([['a1',process.env.IDENTITY_LEGACY_A1_RESPONSE_KEY],['server',process.env.IDENTITY_LEGACY_SERVER_RESPONSE_KEY]].filter((entry):entry is [string,string]=>typeof entry[1]==='string').map(([consumer,encoded])=>[consumer,graphEncryptionKey(encoded)])):undefined;
 const apply=args.includes('--apply');if(apply&&process.env.NODE_ENV!=='staging')throw new Error();
 // Production offline target is exact approved development private database.
 if(process.env.IDENTITY_DB_HOST!=='10.206.0.5'||(process.env.IDENTITY_DB_PORT??'3306')!=='3306'||process.env.IDENTITY_DB_NAME!=='xrugc_identity_dev'||process.env.IDENTITY_DB_USER!=='identity_dev')throw new Error();
 const target=await connectLegacySessionImportTarget(),reader=new LegacyIdentityReader();try{
 const [actor]=await target.query<any[]>('SELECT CURRENT_USER() AS actor');if(actor[0]?.actor!=='identity_dev@%')throw new Error();
 console.log(JSON.stringify(await importRefreshGraph(target,manifest,accounts,{apply,reviewedSha256:apply?get('reviewed-sha256'):undefined,sourceResponseKeys:sourceKeys,sourceResponseKey:sourceKey?graphEncryptionKey(sourceKey):undefined,assertDeviceSnAuthorized:(sn,uid)=>reader.assertDeviceSnAuthorized(sn,uid,true)})));
 }finally{await target.end();await reader.onModuleDestroy();}
}
main().catch(()=>{console.error("Offline legacy refresh graph import failed. Review protected source evidence, current SQL epoch, source signer/MAC, private authority and retained tombstones. No credential-bearing errors are logged.");process.exitCode=1;});
