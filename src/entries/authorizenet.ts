/** `verihook/authorizenet`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { authorizenetVerifier } from "../providers/authorizenet.js";

export const verifyAuthorizeNet: ProviderVerifyFunction<"authorizenet"> =
  bindVerifier("authorizenet", authorizenetVerifier);

export { authorizenetVerifier };
export type { AuthorizeNetEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
