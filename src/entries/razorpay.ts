/** `verihook/razorpay`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { razorpayVerifier } from "../providers/razorpay.js";

export const verifyRazorpay: ProviderVerifyFunction<"razorpay"> = bindVerifier(
  "razorpay",
  razorpayVerifier,
);

export { razorpayVerifier };
export type { RazorpayEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
