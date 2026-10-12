import mysql, { type RowDataPacket } from "mysql2/promise";
import { writeFile } from "node:fs/promises";
import { loadConfig } from "../apps/identity-adapter/src/config.js";
import { profileGroupSha256, type ProfileSelectionManifest } from "../apps/identity-adapter/src/identity-profile-migration.js";
import { assertProfileJsonValues, legacyProfileJsonTypeSelection } from "../apps/identity-adapter/src/identity-profile-source.js";

/** Capture for review only. This does not import data or activate authority. */
async function main() {
  const args=process.argv.slice(2);
  const usage="profile-selection-capture --out=<new-protected.json> [--max-rows=<1..1000000>]";
  if(args.includes("--help")){console.log(usage);return;}
  if(args.some(arg=>!arg.startsWith("--out=")&&!/^--max-rows=\d+$/.test(arg))
    ||args.filter(arg=>arg.startsWith("--out=")).length!==1||args.filter(arg=>arg.startsWith("--max-rows=")).length>1)throw new Error(usage);
  const output=args.find(arg=>arg.startsWith("--out="))!.slice("--out=".length);
  const maxRows=Number(args.find(arg=>arg.startsWith("--max-rows="))?.slice("--max-rows=".length)??100000);
  if(!output||!Number.isSafeInteger(maxRows)||maxRows<1||maxRows>1000000)throw new Error(usage);
  const db=loadConfig().legacyDb;
  if(!db.host||!db.user)throw new Error("Explicit read-only source is required");
  const source=await mysql.createConnection({host:db.host,port:db.port,user:db.user,password:db.password,database:db.name,timezone:"Z"});
  try {
    await source.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
    await source.query("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
    const [columns]=await source.query<RowDataPacket[]>("SHOW COLUMNS FROM user_info");
    const hasAvatarColumn=columns.some(column=>column.Field==="avatar_id");
    const [rows]=await source.query<RowDataPacket[]>(`SELECT id,user_id,info${hasAvatarColumn?",avatar_id":""}${legacyProfileJsonTypeSelection(columns)} FROM user_info ORDER BY id LIMIT ${maxRows+1}`);
    if(rows.length>maxRows)throw new Error("Profile capture exceeds its row bound");
    assertProfileJsonValues(rows,true);
    const groups=new Map<number,RowDataPacket[]>();
    for(const row of rows){const owner=Number(row.user_id);groups.set(owner,[...(groups.get(owner)??[]),row]);}
    const manifest:ProfileSelectionManifest={version:1,selections:[]};
    for(const [owner,group]of groups){
      if(group.length<2)continue;
      // Preserve the historical projections: selecting only the covering index's
      // ID can change LIMIT 1's query plan and therefore the observed profile.
      const [yii]=await source.query<RowDataPacket[]>("SELECT * FROM user_info WHERE user_id=? LIMIT 1",[owner]);
      const identitySql=`SELECT u.id, u.username, u.email, u.status, u.nickname,
        u.email_verified_at AS emailVerifiedAt, u.created_at AS createdAt,
        u.updated_at AS updatedAt, ui.info AS userInfo
        FROM user u LEFT JOIN user_info ui ON ui.user_id = u.id WHERE u.id = ? LIMIT 1`;
      const [identity]=await source.query<RowDataPacket[]>(identitySql,[owner]);
      const [identityWithId]=await source.query<RowDataPacket[]>(identitySql.replace("ui.info AS userInfo", "ui.info AS userInfo, ui.id AS profileId"),[owner]);
      const selected=group.find(row=>String(row.id)===String(yii[0]?.id));
      const sameInfo=selected&&identity[0]&&profileGroupSha256([{...selected,info:identity[0].userInfo}],hasAvatarColumn)
        ===profileGroupSha256([selected],hasAvatarColumn);
      if(!selected||!sameInfo||String(yii[0].id)!==String(identityWithId[0]?.profileId))throw new Error("Profile capture reader shapes disagree; explicit review is required");
      manifest.selections.push({userId:owner,profileId:Number(yii[0].id),sourceRowsSha256:profileGroupSha256(group,hasAvatarColumn)});
    }
    await writeFile(output,`${JSON.stringify(manifest,null,2)}\n`,{flag:"wx",mode:0o600});
    console.log(JSON.stringify({written:true,sourceRows:rows.length,owners:groups.size,duplicateGroups:manifest.selections.length,
      matchingReadShapes:true,selectedProfileIds:manifest.selections.map(selection=>selection.profileId),sourceWrites:0,applied:false}));
  }finally{await source.rollback();await source.end();}
}
main().catch(()=>{console.error("Read-only profile selection capture failed; no source data or existing manifest was overwritten.");process.exitCode=1;});
