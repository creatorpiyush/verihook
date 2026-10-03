/** `verihook/linear`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { linearVerifier } from "../providers/linear.js";

export const verifyLinear = bindVerifier("linear", linearVerifier);

export { linearVerifier };
export type { LinearEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
