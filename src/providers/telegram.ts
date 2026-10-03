/**
 * Telegram Bot API webhooks.
 *
 * Telegram doesn't sign updates. It sends the `secret_token` you passed to
 * `setWebhook` in a header, which proves the request came from the webhook you set:
 *   X-Telegram-Bot-Api-Secret-Token: <secret_token>
 * `result.eventType` is the update kind (e.g. `message`, `callback_query`).
 * https://core.telegram.org/bots/api#setwebhook
 */
import { timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";

export const telegramVerifier: ProviderVerifier = {
  name: "telegram",
  eventType: (event) => {
    if (!event || typeof event !== "object") return undefined;
    return Object.keys(event).find((key) => key !== "update_id");
  },
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const token = req.headers["x-telegram-bot-api-secret-token"];
    if (!token) {
      return {
        valid: false,
        provider: "telegram",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "x-telegram-bot-api-secret-token" header (set secret_token in setWebhook)',
      };
    }

    if (!timingSafeEqual(token, secret)) {
      return {
        valid: false,
        provider: "telegram",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Secret token mismatch",
      };
    }

    return { valid: true, provider: "telegram" };
  },
};
