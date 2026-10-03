/** `verihook/checkout`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { checkoutVerifier } from "../providers/checkout.js";

export const verifyCheckout: ProviderVerifyFunction<"checkout"> = bindVerifier(
  "checkout",
  checkoutVerifier,
);

export { checkoutVerifier };
export type { CheckoutEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
