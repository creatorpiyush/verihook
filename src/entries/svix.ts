/** `verihook/svix`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { svixVerifier } from "../providers/svix.js";

export const verifySvix: ProviderVerifyFunction<"svix"> = bindVerifier(
  "svix",
  svixVerifier,
);
export const verifyResend: ProviderVerifyFunction<"resend"> = bindVerifier(
  "resend",
  svixVerifier,
);
export const verifyClerk: ProviderVerifyFunction<"clerk"> = bindVerifier(
  "clerk",
  svixVerifier,
);

export { svixVerifier };
export type { SvixEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
