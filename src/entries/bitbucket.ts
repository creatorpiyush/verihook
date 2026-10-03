/** `verihook/bitbucket`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { bitbucketVerifier } from "../providers/bitbucket.js";

export const verifyBitbucket: ProviderVerifyFunction<"bitbucket"> =
  bindVerifier("bitbucket", bitbucketVerifier);

export { bitbucketVerifier };
export type { BitbucketEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
