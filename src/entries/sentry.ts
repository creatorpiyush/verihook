/** `verihook/sentry`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { sentryVerifier } from "../providers/sentry.js";

export const verifySentry = bindVerifier("sentry", sentryVerifier);

export { sentryVerifier };
export type { SentryEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
