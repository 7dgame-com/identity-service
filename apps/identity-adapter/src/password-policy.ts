const weakPasswords = [
  "password123",
  "password123!",
  "password123!",
  "admin123456!",
  "qwerty123!",
  "qwerty123456!",
  "abc123456789!",
  "welcome12345!",
  "changeme1234!",
  "letmein12345!",
  "master123456!",
  "dragon123456!",
  "monkey123456!",
  "shadow123456!",
  "sunshine12345",
  "princess1234!",
  "football1234!",
  "charlie12345!",
  "passw0rd1234!",
  "iloveyou1234!",
  "trustno12345!",
  "123456789aa!",
  "abcdef123456!",
  "qwerty!@#$12",
  "admin!@#$1234",
  "p@ssw0rd1234",
  "p@$$w0rd1234",
  "test12345678!",
  "hello1234567!"
];

export interface PasswordPolicyContext {
  username?: string | null;
  email?: string | null;
}

export function validatePasswordPolicy(password: string, context: PasswordPolicyContext = {}): string[] {
  const errors: string[] = [];

  if (password.length < 8) {
    errors.push("密码长度不能少于 8 个字符");
  }
  if (password.length > 64) {
    errors.push("密码长度不能超过 64 个字符");
  }
  if (countCharacterCategories(password) < 3) {
    errors.push("密码必须在大写字母、小写字母、数字、特殊字符中至少包含 3 类");
  }
  if (weakPasswords.includes(password.toLowerCase())) {
    errors.push("该密码过于常见，请选择更安全的密码");
  }
  if (containsAccountIdentifier(password, context)) {
    errors.push("密码不能包含用户名或邮箱信息");
  }

  return errors;
}

function countCharacterCategories(password: string): number {
  return [
    /[A-Z]/.test(password),
    /[a-z]/.test(password),
    /\d/.test(password),
    /[\W_]/.test(password)
  ].filter(Boolean).length;
}

function containsAccountIdentifier(password: string, context: PasswordPolicyContext): boolean {
  const identifiers = normalizeAccountIdentifiers(context);
  if (identifiers.length === 0) {
    return false;
  }

  const lowerPassword = password.toLowerCase();
  return identifiers.some((identifier) => lowerPassword.includes(identifier));
}

function normalizeAccountIdentifiers(context: PasswordPolicyContext): string[] {
  const raw = [context.username, context.email].filter((value): value is string => typeof value === "string");
  const identifiers = new Set<string>();
  for (const value of raw) {
    const lower = value.trim().toLowerCase();
    addIdentifier(identifiers, lower);
    const [prefix] = lower.split("@", 2);
    addIdentifier(identifiers, prefix);
  }

  return [...identifiers];
}

function addIdentifier(identifiers: Set<string>, value: string | undefined): void {
  if (value && value.length >= 3) {
    identifiers.add(value);
  }
}
