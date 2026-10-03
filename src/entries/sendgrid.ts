/** `verihook/sendgrid`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { sendgridVerifier } from "../providers/sendgrid.js";

export const verifySendGrid: ProviderVerifyFunction<"sendgrid"> = bindVerifier(
  "sendgrid",
  sendgridVerifier,
);

export { sendgridVerifier };
export type { SendGridEvent, SendGridEventItem } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
