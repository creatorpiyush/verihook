/** `verihook/mollie`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { mollieVerifier } from "../providers/mollie.js";

export const verifyMollie: ProviderVerifyFunction<"mollie"> = bindVerifier(
  "mollie",
  mollieVerifier,
);

export { mollieVerifier };
export type { MollieEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
