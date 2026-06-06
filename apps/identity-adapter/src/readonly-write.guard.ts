const WRITE_SQL_PATTERN =
  /\b(insert|update|delete|replace|alter|drop|truncate|create|rename|grant|revoke|lock|unlock)\b/i;

export function assertReadonlySql(sql: string): void {
  if (WRITE_SQL_PATTERN.test(sql)) {
    throw new Error(`Readonly identity-adapter blocked write-like SQL: ${sql.slice(0, 80)}`);
  }
}

