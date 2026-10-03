/** `verihook/twilio`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { twilioVerifier } from "../providers/twilio.js";

export const verifyTwilio: ProviderVerifyFunction<"twilio"> = bindVerifier(
  "twilio",
  twilioVerifier,
);

export { twilioVerifier };
export type { TwilioEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
