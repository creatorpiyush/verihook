/** `verihook/pagerduty`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { pagerdutyVerifier } from "../providers/pagerduty.js";

export const verifyPagerDuty: ProviderVerifyFunction<"pagerduty"> =
  bindVerifier("pagerduty", pagerdutyVerifier);

export { pagerdutyVerifier };
export type { PagerDutyEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
