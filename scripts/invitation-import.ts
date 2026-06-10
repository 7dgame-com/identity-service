import "reflect-metadata";
import { InvitationIdentityRepository } from "../apps/identity-adapter/src/invitation-identity.repository.js";
import { InvitationImportService } from "../apps/identity-adapter/src/invitation-import.service.js";
import { InvitationRedisReader } from "../apps/identity-adapter/src/invitation-redis.reader.js";

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const redisReader = new InvitationRedisReader();
  const repository = new InvitationIdentityRepository();
  const importer = new InvitationImportService(redisReader, repository);

  try {
    const result = await importer.importFromLegacy({
      code: args.code,
      apply: args.apply
    });
    console.log(JSON.stringify(result, null, 2));

    if (!result.sourceConfigured || !result.identityDbConfigured) {
      process.exitCode = 2;
    }
  } finally {
    await repository.onModuleDestroy();
  }
}

interface InvitationImportArgs {
  apply: boolean;
  code: string | null;
  help: boolean;
}

function parseArgs(args: string[]): InvitationImportArgs {
  const parsed: InvitationImportArgs = {
    apply: false,
    code: null,
    help: false
  };

  for (const arg of args) {
    if (arg === "--apply") {
      parsed.apply = true;
      continue;
    }
    if (arg === "--dry-run") {
      parsed.apply = false;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }
    if (arg.startsWith("--code=")) {
      parsed.code = arg.slice("--code=".length).trim() || null;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

function printHelp(): void {
  console.log(`Usage:
  npm run invitation:import -- [--dry-run] [--apply] [--code=<invite-code>]

Default mode is dry-run. Dry-run scans legacy Redis invite:* and compares with
identity DB identity_invitations without writing data.

Required env:
  IDENTITY_INVITATION_REDIS_URL=redis://host:6379/0
  IDENTITY_DB_HOST=...
  IDENTITY_DB_NAME=xrugc_identity
  IDENTITY_DB_USER=identity
  IDENTITY_DB_PASSWORD=...
`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
