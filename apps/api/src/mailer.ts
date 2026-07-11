import type { ApiConfig } from "./config.js";

export interface LoginCodeMailer {
  sendLoginCode(email: string, code: string): Promise<void>;
}

export class MailDeliveryError extends Error {
  constructor() {
    super("mail_delivery_failed");
    this.name = "MailDeliveryError";
  }
}

export function createLoginCodeMailer(config: ApiConfig): LoginCodeMailer {
  if (!config.resendApiKey || !config.resendFromEmail) {
    return { sendLoginCode: async () => undefined };
  }

  return {
    async sendLoginCode(email, code) {
      let response: Response;
      try {
        response = await fetch(config.resendApiUrl, {
          method: "POST",
          headers: {
            authorization: `Bearer ${config.resendApiKey}`,
            "content-type": "application/json"
          },
          body: JSON.stringify({
            from: config.resendFromEmail,
            to: [email],
            subject: "Your Forge Agent sign-in code",
            text: `Your Forge Agent sign-in code is ${code}. It expires in 10 minutes. If you did not request this code, you can ignore this email.`
          }),
          signal: AbortSignal.timeout(10_000)
        });
      } catch {
        throw new MailDeliveryError();
      }

      if (!response.ok) throw new MailDeliveryError();
    }
  };
}
