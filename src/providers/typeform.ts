/**
 * Typeform webhooks.
 *
 * Typeform signs the raw body with HMAC-SHA256, keyed with the webhook secret, and
 * sends the base64 digest:
 *   Typeform-Signature: sha256=<base64 digest>
 * https://www.typeform.com/developers/webhooks/secure-your-webhooks/
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64 } from "../utils/encoding.js";

export const typeformVerifier: ProviderVerifier = {
  name: "typeform",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["typeform-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "typeform",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "typeform-signature" header',
      };
    }

    const expected = bytesToBase64(
      await computeHmacSha256(secret, req.rawBody),
    );
    const signature = header.trim().replace(/^sha256=/i, "");

    if (!timingSafeEqual(signature, expected)) {
      return {
        valid: false,
        provider: "typeform",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "typeform" };
  },
};
