import { readFile,stat,writeFile } from "node:fs/promises";
import { exportYii3RefreshSessions } from "../apps/identity-adapter/src/identity-yii3-session-export.js";
import { normalizeLegacySessionManifest } from "../apps/identity-adapter/src/legacy-session-import.js";

async function main(){
  const args=process.argv.slice(2);
  if(args.length!==2||args.filter(arg=>arg.startsWith("--snapshot=")).length!==1||args.filter(arg=>arg.startsWith("--out=")).length!==1)
    throw new Error("Usage: yii3-session-export --snapshot=<protected.json> --out=<new-protected-manifest.json>");
  const input=args.find(arg=>arg.startsWith("--snapshot="))!.slice(11),output=args.find(arg=>arg.startsWith("--out="))!.slice(6);
  const metadata=await stat(input);
  if(!metadata.isFile()||metadata.size>64*1024*1024||(metadata.mode&0o077)!==0)throw new Error("Snapshot must be a bounded owner-only regular file.");
  const exported=exportYii3RefreshSessions(JSON.parse(await readFile(input,"utf8")));
  normalizeLegacySessionManifest(exported.manifest);
  await writeFile(output,JSON.stringify(exported.manifest,null,2)+"\n",{mode:0o600,flag:"wx"});
  console.log(JSON.stringify({written:true,...exported.report}));
}
main().catch(()=>{console.error("Offline Yii3 refresh export failed; source data and existing files were not changed.");process.exitCode=1;});
