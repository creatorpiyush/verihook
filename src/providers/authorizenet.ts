/**
 * Authorize.net (USA) webhooks.
 *
 * Authorize.net signs the raw body with HMAC-SHA512, keyed with the merchant's
 * Signature Key (used as-is), and sends the uppercase hex digest:
 *   X-ANET-Signature: sha512=<HEX DIGEST>
 * https://developer.authorize.net/api/reference/features/webhooks.html
 */
import { computeHmacSha512, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const authorizenetVerifier: ProviderVerifier = {
  name: "authorizenet",
  eventType: (event) => readString(event, "eventType"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["x-anet-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "authorizenet",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-anet-signature" header',
      };
    }

    const signature = header
      .trim()
      .replace(/^sha512=/i, "")
      .toLowerCase();
    const expected = bytesToHex(await computeHmacSha512(secret, req.rawBody));

    if (!timingSafeEqual(signature, expected)) {
      return {
        valid: false,
        provider: "authorizenet",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "authorizenet" };
  },
};
