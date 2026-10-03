/** `verihook/webflow`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { webflowVerifier } from "../providers/webflow.js";

export const verifyWebflow = bindVerifier("webflow", webflowVerifier);

export { webflowVerifier };
export type { WebflowEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
