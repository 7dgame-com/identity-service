import { BadRequestException, Injectable, ServiceUnavailableException } from "@nestjs/common";
import { connect, type Socket } from "node:net";
import nodemailer from "nodemailer";
import type { SMTPTransportOptions } from "nodemailer/lib/smtp-transport";
import { z } from "zod";
import { loadConfig } from "./config.js";
import { renderCodeEmail, type CodeEmailType } from "./email-content.js";

const deliveryBudgetMs = 3000;
const recipient = z.string().email().max(255).regex(/^[^\s,;<>\r\n]+$/);

export interface PasswordResetCodeEmail {
  email: string;
  code: string;
  locale?: string;
  i18n?: Record<string, unknown>;
}

export interface EmailVerificationCodeEmail {
  email: string;
  code: string;
  locale?: string;
  i18n?: Record<string, unknown>;
}

@Injectable()
export class EmailDeliveryService {
  private readonly config = loadConfig();

  isConfigured(): boolean {
    const delivery = this.config.emailDelivery;
    if (delivery.transport === "webhook") return Boolean(delivery.webhookUrl);
    return Boolean(delivery.smtp.host && delivery.smtp.username && delivery.smtp.password && delivery.smtp.from);
  }

  async sendPasswordResetCode(input: PasswordResetCodeEmail): Promise<void> {
    return this.sendCodeEmail("password_reset_code", input);
  }

  async sendEmailVerificationCode(input: EmailVerificationCodeEmail): Promise<void> {
    return this.sendCodeEmail("email_verification_code", input);
  }

  private async sendCodeEmail(type: CodeEmailType, input: PasswordResetCodeEmail | EmailVerificationCodeEmail): Promise<void> {
    if (this.config.emailDelivery.transport === "smtp") return this.sendSmtp(type, input);
    return this.sendWebhook(type, input);
  }

  private async sendSmtp(type: CodeEmailType, input: PasswordResetCodeEmail | EmailVerificationCodeEmail): Promise<void> {
    if (!this.isConfigured()) throw new ServiceUnavailableException({ code: "EMAIL_SMTP_NOT_CONFIGURED", message: "Email SMTP delivery is not configured." });
    if (!recipient.safeParse(input.email).success || !/^\d{6}$/.test(input.code) || input.code.length !== 6) {
      throw new BadRequestException({ code: "EMAIL_SMTP_INVALID_MESSAGE", message: "Email message is invalid." });
    }
    const smtp = this.config.emailDelivery.smtp;
    const ttl = type === "password_reset_code" ? this.config.passwordReset.codeTtlSeconds : this.config.emailVerification.codeTtlSeconds;
    const content = renderCodeEmail(type, input, smtp.appName, ttl);
    const controller = new AbortController();
    let socket: Socket | undefined;
    let timedOut = false;
    const options: SMTPTransportOptions = {
      host: smtp.host, port: smtp.port, secure: smtp.tlsMode === "implicit", requireTLS: smtp.tlsMode === "starttls",
      auth: { user: smtp.username, pass: smtp.password },
      tls: { minVersion: "TLSv1.2", rejectUnauthorized: true, servername: smtp.serverName ?? smtp.host },
      connectionTimeout: deliveryBudgetMs, greetingTimeout: deliveryBudgetMs,
      socketTimeout: deliveryBudgetMs, dnsTimeout: deliveryBudgetMs,
      logger: false, debug: false, disableFileAccess: true, disableUrlAccess: true,
      // The documented socket hook lets the total deadline cancel an active send,
      // rather than merely abandoning a promise while the server keeps receiving it.
      getSocket: (_options, callback) => {
        if (controller.signal.aborted) return callback(new Error("Email delivery deadline exceeded"));
        socket = connect({ host: smtp.host, port: smtp.port, signal: controller.signal });
        const onError = (error: Error) => callback(error);
        socket.once("error", onError);
        socket.once("connect", () => {
          socket!.removeListener("error", onError);
          callback(null, { connection: socket });
        });
      }
    };
    const transporter = nodemailer.createTransport(options);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        timedOut = true;
        reject(new Error("Email delivery deadline exceeded"));
        controller.abort();
        socket?.destroy();
      }, deliveryBudgetMs);
    });
    try {
      const result = await Promise.race([transporter.sendMail({
        from: { name: `${smtp.appName} 团队`, address: smtp.from! },
        to: [{ address: input.email, name: "" }],
        envelope: { from: smtp.from!, to: [input.email] },
        ...content
      }), deadline]);
      if (result.accepted.length !== 1 || result.rejected.length !== 0) {
        throw Object.assign(new Error("Email delivery rejected"), { code: "EENVELOPE" });
      }
    } catch (error) {
      const code = typeof error === "object" && error !== null && "code" in error ? error.code : undefined;
      const responseCode = typeof error === "object" && error !== null && "responseCode" in error ? error.responseCode : undefined;
      if (timedOut || code === "ETIMEDOUT") throw new ServiceUnavailableException({ code: "EMAIL_SMTP_TIMEOUT", message: "Email SMTP delivery timed out." });
      if (code === "EAUTH" || code === "EENVELOPE" || (typeof responseCode === "number" && responseCode >= 400 && responseCode <= 599)) {
        throw new ServiceUnavailableException({ code: "EMAIL_SMTP_REJECTED", message: "Email SMTP delivery rejected the request." });
      }
      throw new ServiceUnavailableException({ code: "EMAIL_SMTP_UNAVAILABLE", message: "Email SMTP delivery is unavailable." });
    } finally {
      clearTimeout(timer);
      controller.abort();
      socket?.destroy();
      transporter.close();
    }
  }

  private async sendWebhook(type: CodeEmailType, input: PasswordResetCodeEmail | EmailVerificationCodeEmail): Promise<void> {
    if (!this.config.emailDelivery.webhookUrl) {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_NOT_CONFIGURED",
        message: "Email delivery webhook is not configured."
      });
    }

    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": "application/json"
    });
    if (this.config.emailDelivery.webhookToken) {
      headers.set("Authorization", `Bearer ${this.config.emailDelivery.webhookToken}`);
    }

    let response: Response;
    try {
      response = await fetch(this.config.emailDelivery.webhookUrl, {
        method: "POST",
        redirect: "error",
        headers,
        body: JSON.stringify({
          type,
          email: input.email,
          code: input.code,
          locale: input.locale ?? "en-US",
          i18n: input.i18n ?? {}
        }),
        signal: AbortSignal.timeout(deliveryBudgetMs)
      });
    } catch {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_UNAVAILABLE",
        message: "Email delivery webhook is unavailable."
      });
    }

    if (!response.ok) {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_REJECTED",
        message: "Email delivery webhook rejected the request.",
        status: response.status
      });
    }
  }
}
