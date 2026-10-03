/** `verihook/telegram`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { telegramVerifier } from "../providers/telegram.js";

export const verifyTelegram: ProviderVerifyFunction<"telegram"> = bindVerifier(
  "telegram",
  telegramVerifier,
);

export { telegramVerifier };
export type { TelegramEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
