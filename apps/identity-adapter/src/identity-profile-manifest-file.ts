import { readFile, stat } from "node:fs/promises";
import type { ProfileSelectionManifest } from "./identity-profile-migration.js";

export async function readProfileSelectionFile(filename?: string): Promise<ProfileSelectionManifest | undefined> {
  if (!filename) return undefined;
  const metadata=await stat(filename);
  if(!metadata.isFile()||metadata.size>2*1024*1024)throw new Error("Profile selection manifest must be a bounded regular file");
  return JSON.parse(await readFile(filename,"utf8")) as ProfileSelectionManifest;
}
