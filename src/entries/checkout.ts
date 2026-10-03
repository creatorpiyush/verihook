/** `verihook/checkout`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { checkoutVerifier } from "../providers/checkout.js";

export const verifyCheckout = bindVerifier("checkout", checkoutVerifier);

export { checkoutVerifier };
export type { CheckoutEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
