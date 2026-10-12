import "reflect-metadata";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EmailDeliveryService } from "../src/email-delivery.service.js";
import { loadConfig } from "../src/config.js";
import { renderCodeEmail } from "../src/email-content.js";
import { AccountEmailService } from "../src/account-email.service.js";
import { AccountPasswordResetService } from "../src/account-password-reset.service.js";

const smtp = vi.hoisted(() => ({ create: vi.fn(), send: vi.fn(), close: vi.fn() }));
vi.mock("nodemailer", () => ({ default: { createTransport: smtp.create } }));
const email = "recipient@example.test", code = "123456", password = "fixture-smtp-password";
const envKeys = ["IDENTITY_EMAIL_TRANSPORT", "IDENTITY_EMAIL_WEBHOOK_URL", "IDENTITY_EMAIL_WEBHOOK_TOKEN", "MAILER_USERNAME", "MAILER_PASSWORD",
  "IDENTITY_EMAIL_SMTP_HOST", "IDENTITY_EMAIL_SMTP_PORT", "IDENTITY_EMAIL_SMTP_TLS_MODE", "IDENTITY_EMAIL_SMTP_SERVER_NAME", "IDENTITY_EMAIL_FROM", "IDENTITY_EMAIL_APP_NAME"];
const enableSmtp = () => {
  vi.stubEnv("IDENTITY_EMAIL_TRANSPORT", "smtp"); vi.stubEnv("MAILER_USERNAME", "sender@example.test"); vi.stubEnv("MAILER_PASSWORD", password);
};
const failure = async (promise: Promise<void>) => {
  try { await promise; throw new Error("Expected delivery failure"); } catch (error) {
    expect(error).toHaveProperty("getResponse");
    const result = (error as { getResponse(): unknown }).getResponse();
    const json = JSON.stringify(result);
    for (const secret of [email, code, password, "smtp-secret-response"]) expect(json).not.toContain(secret);
    return result;
  }
};

describe("native SMTP and compatible webhook email delivery", () => {
  beforeEach(() => {
    for (const key of envKeys) vi.stubEnv(key, undefined);
    smtp.create.mockReset().mockReturnValue({ sendMail: smtp.send, close: smtp.close });
    smtp.send.mockReset().mockResolvedValue({ accepted: [email], rejected: [] }); smtp.close.mockReset();
  });
  afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

  it("keeps webhook the default and does not implicitly activate existing MAILER credentials", async () => {
    vi.stubEnv("MAILER_USERNAME", "sender@example.test"); vi.stubEnv("MAILER_PASSWORD", password);
    const service = new EmailDeliveryService(); expect(service.isConfigured()).toBe(false);
    expect(await failure(service.sendPasswordResetCode({ email, code }))).toMatchObject({ code: "EMAIL_WEBHOOK_NOT_CONFIGURED" });
    expect(smtp.create).not.toHaveBeenCalled();
  });
  it("preserves the webhook payload, bearer auth and three-second timeout", async () => {
    vi.stubEnv("IDENTITY_EMAIL_WEBHOOK_URL", "https://mail.example.test/send"); vi.stubEnv("IDENTITY_EMAIL_WEBHOOK_TOKEN", "fixture-webhook-token");
    const fetcher = vi.fn().mockResolvedValue(new Response(null, { status: 204 })); vi.stubGlobal("fetch", fetcher);
    const service = new EmailDeliveryService(); expect(service.isConfigured()).toBe(true);
    await service.sendEmailVerificationCode({ email, code, locale: "zh-CN", i18n: { "zh-CN": { title: "验证邮箱" } } });
    const [url, request] = fetcher.mock.calls[0];
    expect(url).toBe("https://mail.example.test/send"); expect(request.redirect).toBe("error"); expect(request.signal).toBeInstanceOf(AbortSignal);
    expect(new Headers(request.headers).get("Authorization")).toBe("Bearer fixture-webhook-token");
    expect(JSON.parse(request.body)).toEqual({ type: "email_verification_code", email, code, locale: "zh-CN", i18n: { "zh-CN": { title: "验证邮箱" } } });
    expect(smtp.create).not.toHaveBeenCalled();
  });
  it("returns a sanitized webhook outage without exposing a URL or upstream exception", async () => {
    vi.stubEnv("IDENTITY_EMAIL_WEBHOOK_URL", "https://mail.example.test/send");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error(`${password} ${email} ${code}`)));
    expect(await failure(new EmailDeliveryService().sendPasswordResetCode({ email, code }))).toEqual({ code: "EMAIL_WEBHOOK_UNAVAILABLE", message: "Email delivery webhook is unavailable." });
  });
  it("marks SMTP ready only for complete selected SMTP configuration and never falls back", async () => {
    vi.stubEnv("IDENTITY_EMAIL_TRANSPORT", "smtp"); vi.stubEnv("IDENTITY_EMAIL_WEBHOOK_URL", "https://mail.example.test/send");
    const fetcher = vi.fn(); vi.stubGlobal("fetch", fetcher);
    expect(new EmailDeliveryService().isConfigured()).toBe(false);
    vi.stubEnv("MAILER_USERNAME", "sender@example.test"); expect(new EmailDeliveryService().isConfigured()).toBe(false);
    vi.stubEnv("MAILER_PASSWORD", password); const service = new EmailDeliveryService(); expect(service.isConfigured()).toBe(true);
    await service.sendPasswordResetCode({ email, code }); expect(fetcher).not.toHaveBeenCalled();
  });
  it("uses the reviewed enterprise SMTP defaults with verified implicit TLS and one recipient", async () => {
    enableSmtp(); const logs = vi.spyOn(console, "log"), errors = vi.spyOn(console, "error");
    await new EmailDeliveryService().sendEmailVerificationCode({ email, code });
    expect(smtp.create.mock.calls[0][0]).toMatchObject({ host: "smtp.exmail.qq.com", port: 465, secure: true, requireTLS: false,
      tls: { minVersion: "TLSv1.2", rejectUnauthorized: true, servername: "smtp.exmail.qq.com" },
      auth: { user: "sender@example.test", pass: password }, connectionTimeout: 3000, greetingTimeout: 3000, socketTimeout: 3000, dnsTimeout: 3000,
      logger: false, debug: false, disableFileAccess: true, disableUrlAccess: true });
    expect(smtp.send.mock.calls[0][0]).toMatchObject({ from: { address: "sender@example.test", name: "XR UGC平台 团队" },
      to: [{ address: email, name: "" }], envelope: { from: "sender@example.test", to: [email] }, subject: "Email Verification Code - XR UGC平台" });
    expect(smtp.send.mock.calls[0][0].text).toContain(`${code}\n`); expect(smtp.send.mock.calls[0][0].text).toContain("15 minutes");
    expect(smtp.close).toHaveBeenCalledOnce(); expect(logs).not.toHaveBeenCalled(); expect(errors).not.toHaveBeenCalled();
  });
  it("requires STARTTLS without a plaintext or certificate-validation bypass", async () => {
    enableSmtp(); vi.stubEnv("IDENTITY_EMAIL_SMTP_TLS_MODE", "starttls"); vi.stubEnv("IDENTITY_EMAIL_SMTP_PORT", "587");
    await new EmailDeliveryService().sendPasswordResetCode({ email, code });
    expect(smtp.create.mock.calls[0][0]).toMatchObject({ secure: false, requireTLS: true, port: 587, tls: { rejectUnauthorized: true } });
    expect(smtp.create.mock.calls[0][0]).not.toHaveProperty("ignoreTLS");
    expect(smtp.create.mock.calls[0][0]).not.toHaveProperty("opportunisticTLS");
  });
  it.each(["https://attacker.test", "smtp.test/path", "user@smtp.test", "smtp.test\n", "bad..test"])("rejects malformed operator SMTP host %s", (host) => {
    expect(() => loadConfig({ IDENTITY_EMAIL_SMTP_HOST: host })).toThrow();
  });
  it("makes native email and reset readiness recognize SMTP without a webhook", () => {
    enableSmtp(); vi.stubEnv("IDENTITY_ACCOUNT_PASSWORD_RESET_NATIVE_ENABLED", "true"); vi.stubEnv("IDENTITY_ACCOUNT_EMAIL_VERIFY_NATIVE_ENABLED", "true");
    const configured = { isConfigured: () => true };
    const delivery = new EmailDeliveryService();
    const reset = new AccountPasswordResetService(configured as never, configured as never, configured as never, configured as never, {} as never, delivery);
    const verify = new AccountEmailService(configured as never, configured as never, configured as never, delivery, {} as never);
    expect(reset.isResetNativeReady()).toBe(true); expect(verify.isVerifyNativeReady()).toBe(true);
    vi.stubEnv("MAILER_PASSWORD", ""); const unavailable = new EmailDeliveryService();
    expect(new AccountPasswordResetService(configured as never, configured as never, configured as never, configured as never, {} as never, unavailable).isResetNativeReady()).toBe(false);
  });
  it.each(["EAUTH", "EENVELOPE"])("sanitizes SMTP rejection %s and does not retry", async (errorCode) => {
    enableSmtp(); smtp.send.mockRejectedValue(Object.assign(new Error(`${email} ${code} ${password}`), { code: errorCode, response: "smtp-secret-response" }));
    expect(await failure(new EmailDeliveryService().sendPasswordResetCode({ email, code }))).toMatchObject({ code: "EMAIL_SMTP_REJECTED" });
    expect(smtp.send).toHaveBeenCalledOnce(); expect(smtp.close).toHaveBeenCalledOnce();
  });
  it("does not report success if the sole recipient was not accepted", async () => {
    enableSmtp(); smtp.send.mockResolvedValue({ accepted: [], rejected: [email] });
    expect(await failure(new EmailDeliveryService().sendPasswordResetCode({ email, code }))).toMatchObject({ code: "EMAIL_SMTP_REJECTED" });
  });
  it("sanitizes network errors and preserves one send attempt", async () => {
    enableSmtp(); smtp.send.mockRejectedValue(Object.assign(new Error(`${email} ${code} ${password}`), { code: "ESOCKET" }));
    expect(await failure(new EmailDeliveryService().sendPasswordResetCode({ email, code }))).toMatchObject({ code: "EMAIL_SMTP_UNAVAILABLE" });
    expect(smtp.send).toHaveBeenCalledOnce();
  });
  it("enforces an absolute three-second SMTP request budget", async () => {
    enableSmtp(); vi.useFakeTimers(); smtp.send.mockReturnValue(new Promise(() => {}));
    const result = failure(new EmailDeliveryService().sendPasswordResetCode({ email, code }));
    await vi.advanceTimersByTimeAsync(2999); expect(smtp.close).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1); expect(await result).toMatchObject({ code: "EMAIL_SMTP_TIMEOUT" }); expect(smtp.close).toHaveBeenCalledOnce();
  });
  it.each([{ email: `${email},other@example.test`, code }, { email: `${email}\r\nBcc:other@example.test`, code }, { email, code: `${code}\n` }])("rejects recipient/code injection before creating a transport", async (input) => {
    enableSmtp(); expect(await failure(new EmailDeliveryService().sendEmailVerificationCode(input))).toMatchObject({ code: "EMAIL_SMTP_INVALID_MESSAGE" });
    expect(smtp.create).not.toHaveBeenCalled();
  });
});

describe("ported Yii code-email content", () => {
  it("keeps locale fallback, placeholders, security list and escaped HTML", () => {
    const output = renderCodeEmail("password_reset_code", { code, locale: "zh-CN", i18n: { "zh-CN": {
      subject: "{appName}\r\nInjected: no", title: "<script>alert(1)</script>", body: "验证码", expiryText: "{expiryMinutes}分钟", securityItems: ["<b>保密</b>", 1, ""] } } }, "Fixture", 1200);
    expect(output.subject).toBe("Fixture  Injected: no"); expect(output.text).toContain("20分钟"); expect(output.text).toContain("- <b>保密</b>");
    expect(output.html).toContain('lang="zh-CN"'); expect(output.html).toContain("&lt;script&gt;"); expect(output.html).not.toContain("<script>");
    expect(output.html).toContain("&lt;b&gt;保密&lt;/b&gt;");
    const fallback = renderCodeEmail("email_verification_code", { code, locale: "fr-FR", i18n: { "en-US": { title: "English override", securityItems: [] } } }, "Fixture", 900);
    expect(fallback.html).toContain('lang="en-US"'); expect(fallback.text).toContain("English override"); expect(fallback.text).toContain("Do not share this code with anyone.");
  });
});
