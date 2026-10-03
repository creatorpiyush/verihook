/**
 * Checkout.com (Europe) webhooks.
 *
 * Checkout.com signs the raw body with HMAC-SHA256, keyed with the webhook's
 * signature key, and sends the hex digest:
 *   Cko-Signature: <hex digest>
 * The optional `Authorization` header key is not checked; the signature covers it.
 * https://www.checkout.com/docs/workflows/set-up-your-webhook-receiver
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const checkoutVerifier: ProviderVerifier = {
  name: "checkout",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["cko-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "checkout",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "cko-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha256(secret, req.rawBody));

    if (!timingSafeEqual(signature.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "checkout",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "checkout" };
  },
};
