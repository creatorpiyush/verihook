/** `verihook/workos`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { workosVerifier } from "../providers/workos.js";

export const verifyWorkOS = bindVerifier("workos", workosVerifier);

export { workosVerifier };
export type { WorkOSEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
