/** `verihook/zoom`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { zoomVerifier } from "../providers/zoom.js";

export const verifyZoom: ProviderVerifyFunction<"zoom"> = bindVerifier(
  "zoom",
  zoomVerifier,
);

export { zoomVerifier };
export type { ZoomEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
