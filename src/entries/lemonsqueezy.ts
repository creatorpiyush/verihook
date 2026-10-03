/** `verihook/lemonsqueezy`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { lemonsqueezyVerifier } from "../providers/lemonsqueezy.js";

export const verifyLemonSqueezy = bindVerifier(
  "lemonsqueezy",
  lemonsqueezyVerifier,
);

export { lemonsqueezyVerifier };
export type { LemonSqueezyEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
