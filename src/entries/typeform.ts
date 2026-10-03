/** `verihook/typeform`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { typeformVerifier } from "../providers/typeform.js";

export const verifyTypeform = bindVerifier("typeform", typeformVerifier);

export { typeformVerifier };
export type { TypeformEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
