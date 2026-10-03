/** `verihook/hubspot`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { hubspotVerifier } from "../providers/hubspot.js";

export const verifyHubSpot = bindVerifier("hubspot", hubspotVerifier);

export { hubspotVerifier };
export type { HubSpotEvent, HubSpotWebhookEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
