import { Injectable, ServiceUnavailableException } from "@nestjs/common";
import { loadConfig } from "./config.js";

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
    return Boolean(this.config.emailDelivery.webhookUrl);
  }

  async sendPasswordResetCode(input: PasswordResetCodeEmail): Promise<void> {
    return this.sendCodeEmail("password_reset_code", input);
  }

  async sendEmailVerificationCode(input: EmailVerificationCodeEmail): Promise<void> {
    return this.sendCodeEmail("email_verification_code", input);
  }

  private async sendCodeEmail(type: "password_reset_code" | "email_verification_code", input: PasswordResetCodeEmail | EmailVerificationCodeEmail): Promise<void> {
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
        headers,
        body: JSON.stringify({
          type,
          email: input.email,
          code: input.code,
          locale: input.locale ?? "en-US",
          i18n: input.i18n ?? {}
        }),
        signal: AbortSignal.timeout(3000)
      });
    } catch (error) {
      throw new ServiceUnavailableException({
        code: "EMAIL_WEBHOOK_UNAVAILABLE",
        message: "Email delivery webhook is unavailable.",
        detail: error instanceof Error ? error.message : String(error)
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
