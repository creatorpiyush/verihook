/** `verihook/svix`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { svixVerifier } from "../providers/svix.js";

export const verifySvix = bindVerifier("svix", svixVerifier);
export const verifyResend = bindVerifier("resend", svixVerifier);
export const verifyClerk = bindVerifier("clerk", svixVerifier);

export { svixVerifier };
export type { SvixEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
