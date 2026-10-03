/** `verihook/intercom`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { intercomVerifier } from "../providers/intercom.js";

export const verifyIntercom: ProviderVerifyFunction<"intercom"> = bindVerifier(
  "intercom",
  intercomVerifier,
);

export { intercomVerifier };
export type { IntercomEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
