/** `verihook/standard-webhooks`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { standardWebhooksVerifier } from "../providers/standard-webhooks.js";

export const verifyStandardWebhooks: ProviderVerifyFunction<"standard-webhooks"> =
  bindVerifier("standard-webhooks", standardWebhooksVerifier);

export { standardWebhooksVerifier };
export type { SvixEvent as StandardWebhooksEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
