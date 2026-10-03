/** `verihook/vercel`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { vercelVerifier } from "../providers/vercel.js";

export const verifyVercel: ProviderVerifyFunction<"vercel"> = bindVerifier(
  "vercel",
  vercelVerifier,
);

export { vercelVerifier };
export type { VercelEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
