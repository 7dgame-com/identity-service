import mysql from "mysql2/promise";
import { loadConfig } from "../apps/identity-adapter/src/config.js";
import { initializeFreshAllocator } from "../apps/identity-adapter/src/identity-allocator-state.js";
import { AllocatorError } from "../apps/identity-adapter/src/identity-allocator-manifest.js";
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log(
      "allocator-fresh --apply --database=<exact configured private database>. Explicit empty installation only; no source connection or activation.",
    );
    return;
  }
  const config = loadConfig(),
    db = config.identityDb;
  if (
    args.length !== 2 ||
    !args.includes("--apply") ||
    !args.includes("--database=" + db.name) ||
    !db.host ||
    !db.user ||
    !/^[A-Za-z0-9_]{1,64}$/.test(db.name) ||
    db.name === config.legacyDb.name
  )
    throw new Error("Explicit distinct private database confirmation required");
  const c = await mysql.createConnection({
    host: db.host,
    port: db.port,
    database: db.name,
    user: db.user,
    password: db.password,
    connectTimeout: 10000,
    timezone: "Z",
  });
  try {
    await initializeFreshAllocator(c);
    console.log(
      JSON.stringify({
        success: true,
        kind: "fresh",
        ready: true,
        authorityActivated: false,
        sourceConnected: false,
      }),
    );
  } finally {
    await c.end();
  }
}
main().catch((error) => {
  console.error(
    JSON.stringify({
      success: false,
      code:
        error instanceof AllocatorError ? error.code : "ALLOCATOR_FRESH_FAILED",
      authorityActivated: false,
    }),
  );
  process.exitCode = 1;
});
