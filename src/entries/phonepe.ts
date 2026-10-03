/** `verihook/phonepe`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { phonepeVerifier } from "../providers/phonepe.js";

export const verifyPhonePe: ProviderVerifyFunction<"phonepe"> = bindVerifier(
  "phonepe",
  phonepeVerifier,
);

export { phonepeVerifier };
export type { PhonePeEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
