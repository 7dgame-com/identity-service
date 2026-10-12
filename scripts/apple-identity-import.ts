import { readFile } from "node:fs/promises";
import { connectAccountImportDatabases } from "../apps/identity-adapter/src/identity-account-import.js";
import { importLegacyAppleIdentities, type ReviewedAppleManifest } from "../apps/identity-adapter/src/apple-identity-import.js";

const args=process.argv.slice(2),key=args.find(arg=>arg.startsWith("--import-key="))?.slice(13),file=args.find(arg=>arg.startsWith("--manifest="))?.slice(11);
if(!key||(args.includes("--apply")&&args.includes("--dry-run"))||args.some(arg=>arg!=="--apply"&&arg!=="--dry-run"&&!arg.startsWith("--import-key=")&&!arg.startsWith("--manifest=")))throw new Error("Use --import-key=<key> [--manifest=<reviewed-apps.json>] [--apply|--dry-run]; default is read-only inventory");
const manifest=file?JSON.parse(await readFile(file,"utf8")) as ReviewedAppleManifest:undefined;
const {source,target}=await connectAccountImportDatabases();
try{console.log(JSON.stringify(await importLegacyAppleIdentities(source,target,{importKey:key,manifest,apply:args.includes("--apply")})));}
catch{console.error("Apple import failed. A nonempty legacy apple_id table requires a reviewed subject/app manifest; no email, token or password data is logged.");process.exitCode=1;}
finally{await source.end();await target.end();}
