/** `verihook/stripe`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { stripeVerifier } from "../providers/stripe.js";

export const verifyStripe: ProviderVerifyFunction<"stripe"> = bindVerifier(
  "stripe",
  stripeVerifier,
);

export { stripeVerifier };
export type { StripeEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
