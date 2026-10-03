/** `verihook/adyen`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { adyenVerifier } from "../providers/adyen.js";

export const verifyAdyen: ProviderVerifyFunction<"adyen"> = bindVerifier(
  "adyen",
  adyenVerifier,
);

export { adyenVerifier };
export type {
  AdyenEvent,
  AdyenNotificationRequestItem,
} from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
