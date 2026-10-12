export type CodeEmailType = "password_reset_code" | "email_verification_code";

// Same content keys, locale fallback and text/HTML semantics as Yii EmailService.
const verification = {
  subject: "Email Verification Code - {appName}", title: "Email Verification", greeting: "Hello,",
  body: "You are verifying your email address. Your verification code is:", codeLabel: "Verification code",
  expiryText: "Please complete verification within {expiryMinutes} minutes.", securityTitle: "Security notice",
  securityItems: ["Do not share this code with anyone.", "If this was not your action, please ignore this email.",
    "The code will expire in {expiryMinutes} minutes."], footer: "This email was sent automatically. Please do not reply."
};
const reset = {
  ...verification, subject: "Password Reset Code - {appName}", title: "Password Reset Request",
  body: "We received a request to reset your password. Your reset code is:", codeLabel: "Reset code",
  expiryText: "This code expires in {expiryMinutes} minutes.",
  securityItems: ["Do not share this code with anyone.", "If you did not request this, ignore this email and secure your account.",
    "After password reset, you may need to sign in again on your devices."]
};
type Content = typeof verification;
const fields = ["subject", "title", "greeting", "body", "codeLabel", "expiryText", "securityTitle", "footer"] as const;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const escape = (value: string) => value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[character]!);

export function renderCodeEmail(type: CodeEmailType, input: { code: string; locale?: string; i18n?: Record<string, unknown> }, appName: string, ttlSeconds: number) {
  const defaults = type === "password_reset_code" ? reset : verification;
  const requested = /^[a-z]{2}-[A-Z]{2}$/.test(input.locale ?? "") ? input.locale! : "en-US";
  const localized = input.i18n?.[requested], english = input.i18n?.["en-US"];
  const custom = record(localized) ? localized : record(english) ? english : {};
  const locale = record(localized) ? requested : "en-US";
  const replace = (value: string) => value.replaceAll("{appName}", appName).replaceAll("{expiryMinutes}", String(Math.ceil(ttlSeconds / 60)));
  const content: Content = { ...defaults, securityItems: [...defaults.securityItems] };
  for (const field of fields) {
    const value = custom[field];
    content[field] = replace(typeof value === "string" && value.length <= 4000 ? value : defaults[field]);
  }
  const items = Array.isArray(custom.securityItems) ? custom.securityItems.filter((value): value is string =>
    typeof value === "string" && value.length > 0 && value.length <= 4000).slice(0, 20) : [];
  content.securityItems = (items.length ? items : defaults.securityItems).map(replace);
  // Subjects remain one header even when client-provided localized text contains newlines.
  content.subject = content.subject.replace(/[\r\n\x00-\x1f\x7f]/g, " ");
  const copyright = `© ${new Date().getFullYear()} ${appName}. All rights reserved.`;
  const text = [content.title, "================", "", content.greeting, "", content.body, "",
    `${content.codeLabel}: ${input.code}`, "", content.expiryText, "", `${content.securityTitle}:`,
    ...content.securityItems.map((item) => `- ${item}`), "", content.footer, "", copyright].join("\n");
  const html = `<!DOCTYPE html><html lang="${escape(locale)}"><head><meta charset="UTF-8"><title>${escape(content.title)}</title></head><body><main style="max-width:600px;margin:auto;font-family:sans-serif;line-height:1.6"><h1>${escape(content.title)}</h1><p>${escape(content.greeting)}</p><p>${escape(content.body)}</p><section style="padding:24px;text-align:center;border:2px dashed #dee2e6"><div>${escape(content.codeLabel)}</div><strong style="font-size:36px;letter-spacing:8px">${escape(input.code)}</strong><p>${escape(content.expiryText)}</p></section><h2>${escape(content.securityTitle)}</h2><ul>${content.securityItems.map((item) => `<li>${escape(item)}</li>`).join("")}</ul><footer><p>${escape(content.footer)}</p><p>${escape(copyright)}</p></footer></main></body></html>`;
  return { subject: content.subject, text, html };
}
