/** `verihook/twitch`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { twitchVerifier } from "../providers/twitch.js";

export const verifyTwitch = bindVerifier("twitch", twitchVerifier);

export { twitchVerifier };
export type { TwitchEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
