/** `verihook/mailgun`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { mailgunVerifier } from "../providers/mailgun.js";

export const verifyMailgun = bindVerifier("mailgun", mailgunVerifier);

export { mailgunVerifier };
export type { MailgunEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
