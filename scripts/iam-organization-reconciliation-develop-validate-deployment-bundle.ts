#!/usr/bin/env node

import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import {
  validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle
} from "../apps/identity-adapter/src/iam-organization-reconciliation-develop-ci-provenance-deployment-bundle.js";

const MAX_BYTES = 4 * 1024 * 1024;
const KEYS = Object.freeze([
  "ci-provenance", "deployment-evidence", "signer-compose", "runner-compose",
  "docker-inspect-observations"
]);

export async function runOrganizationReconciliationDevelopDeploymentBundleCli(
  argv: readonly string[],
  stdout: Pick<NodeJS.WriteStream, "write"> = process.stdout,
  stderr: Pick<NodeJS.WriteStream, "write"> = process.stderr
): Promise<number> {
  try {
    const paths = parseArguments(argv);
    const values = await Promise.all(KEYS.map((key) => readCanonicalJson(paths[key]!)));
    const report = validateOrganizationReconciliationDevelopCiProvenanceDeploymentBundle({
      ciProvenance: values[0], deploymentEvidence: values[1], signerCompose: values[2],
      runnerCompose: values[3], dockerInspectObservationSet: values[4]
    });
    stdout.write(`${JSON.stringify(report)}\n`);
    return 0;
  } catch {
    stderr.write("invalid-ci-provenance-deployment-bundle\n");
    return 1;
  }
}

function parseArguments(argv: readonly string[]): Record<string, string> {
  if (argv.length !== KEYS.length) throw new Error("invalid");
  const output: Record<string, string> = {};
  for (const argument of argv) {
    const match = /^--([a-z-]+)=(.+)$/.exec(argument);
    if (!match || !KEYS.includes(match[1] as typeof KEYS[number]) || Object.hasOwn(output, match[1])) {
      throw new Error("invalid");
    }
    const path = match[2]!;
    if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.length > 4_096) throw new Error("invalid");
    output[match[1]!] = path;
  }
  if (new Set(Object.values(output)).size !== KEYS.length) throw new Error("invalid");
  return output;
}

async function readCanonicalJson(path: string): Promise<unknown> {
  if (typeof fsConstants.O_NOFOLLOW !== "number" || typeof fsConstants.O_NONBLOCK !== "number") throw new Error("invalid");
  const handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 2 || stat.size > MAX_BYTES) throw new Error("invalid");
    const bytes = Buffer.alloc(stat.size);
    try {
      let offset = 0;
      while (offset < bytes.length) {
        const result = await handle.read(bytes, offset, bytes.length - offset, offset);
        if (result.bytesRead < 1) throw new Error("invalid");
        offset += result.bytesRead;
      }
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      const value = JSON.parse(text) as unknown;
      if (text !== `${JSON.stringify(value)}\n` && text !== `${JSON.stringify(value, null, 2)}\n`) throw new Error("invalid");
      return value;
    } finally {
      bytes.fill(0);
    }
  } finally {
    await handle.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await runOrganizationReconciliationDevelopDeploymentBundleCli(process.argv.slice(2));
}
