import mysql from "mysql2/promise";
import { writeFile } from "node:fs/promises";
import { loadConfig } from "../apps/identity-adapter/src/config.js";
import { readAccountBaseline } from "../apps/identity-adapter/src/identity-account-baseline.js";

async function main(){
  const args=process.argv.slice(2),output=args.find(arg=>arg.startsWith("--out="))?.slice(6);
  if(!output||args.some(arg=>!arg.startsWith("--out=")&&!arg.startsWith("--max-users=")))throw new Error("Usage: account-baseline --out=<new-report.json> [--max-users=100000]");
  const config=loadConfig().legacyDb;if(!config.host||!config.user)throw new Error("Explicit read-only LEGACY_DB configuration is required");
  const source=await mysql.createConnection({host:config.host,port:config.port,user:config.user,password:config.password,database:config.name,timezone:"Z"});
  try{const report=await readAccountBaseline(source,Number(args.find(arg=>arg.startsWith("--max-users="))?.slice(12)??100000));await writeFile(output,JSON.stringify(report,null,2),{mode:0o600,flag:"wx"});console.log(JSON.stringify({written:true,userCount:report.users.count,missingTableCount:report.missingTables.length}));}
  finally{await source.end();}
}
main().catch(()=>{console.error("Read-only account baseline failed; existing reports and source data were not overwritten.");process.exitCode=1;});
