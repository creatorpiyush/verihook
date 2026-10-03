/** `verihook/paypal`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { paypalVerifier } from "../providers/paypal.js";

export const verifyPayPal = bindVerifier("paypal", paypalVerifier);

export { paypalVerifier };
export { clearPayPalCertCache } from "../providers/paypal.js";
export type { PayPalEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
