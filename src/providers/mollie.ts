/**
 * Mollie (Europe) next-gen webhooks.
 *
 * Mollie signs the raw body with HMAC-SHA256, keyed with the endpoint's signing
 * secret, and sends the hex digest:
 *   X-Mollie-Signature: sha256=<hex digest>
 * During a 24-hour secret rotation the request carries two signatures; either may
 * match. Classic Mollie webhooks (a form post with only an `id`) are not signed.
 * https://docs.mollie.com/reference/webhooks-new
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

export const mollieVerifier: ProviderVerifier = {
  name: "mollie",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["x-mollie-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "mollie",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-mollie-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha256(secret, req.rawBody));

    // Repeated headers are joined with ", " by normalizeRequest().
    const signatures = header
      .split(",")
      .map((part) =>
        part
          .trim()
          .replace(/^sha256=/i, "")
          .toLowerCase(),
      )
      .filter(Boolean);

    if (!signatures.some((sig) => timingSafeEqual(sig, expected))) {
      return {
        valid: false,
        provider: "mollie",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "mollie" };
  },
};
