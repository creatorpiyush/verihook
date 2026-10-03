/** `verihook/shopify`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { shopifyVerifier } from "../providers/shopify.js";

export const verifyShopify: ProviderVerifyFunction<"shopify"> = bindVerifier(
  "shopify",
  shopifyVerifier,
);

export { shopifyVerifier };
export type { ShopifyEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
