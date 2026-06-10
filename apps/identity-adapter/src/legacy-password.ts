import bcrypt from "bcryptjs";

export async function hashLegacyPassword(password: string): Promise<string> {
  const hash = await bcrypt.hash(password, 12);
  return hash.startsWith("$2b$") ? `$2y$${hash.slice(4)}` : hash;
}

export async function verifyLegacyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, normalizeLegacyBcryptHash(hash));
}

function normalizeLegacyBcryptHash(hash: string): string {
  return hash.startsWith("$2y$") ? `$2a$${hash.slice(4)}` : hash;
}
