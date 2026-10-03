/** `verihook/postmark`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { postmarkVerifier } from "../providers/postmark.js";

export const verifyPostmark = bindVerifier("postmark", postmarkVerifier);

export { postmarkVerifier };
export type { PostmarkEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
