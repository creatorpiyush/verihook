/** `verihook/slack`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { slackVerifier } from "../providers/slack.js";

export const verifySlack = bindVerifier("slack", slackVerifier);

export { slackVerifier };
export type { SlackEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
