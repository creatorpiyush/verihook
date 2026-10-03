/** `verihook/twitter`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { twitterVerifier } from "../providers/twitter.js";

export const verifyTwitter: ProviderVerifyFunction<"twitter"> = bindVerifier(
  "twitter",
  twitterVerifier,
);
export const verifyX: ProviderVerifyFunction<"twitter"> = verifyTwitter;

export { twitterVerifier };
export { verifyTwitterCrc, verifyXCrc } from "../providers/twitter.js";
export type { TwitterCrcResponse } from "../providers/twitter.js";
export type { TwitterEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
