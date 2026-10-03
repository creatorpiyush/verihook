/**
 * Cashfree Payments (India) webhooks.
 *
 * Cashfree signs `<x-webhook-timestamp><raw body>` (no separator) with HMAC-SHA256,
 * keyed with the merchant's PG client secret, and sends the base64 digest:
 *   x-webhook-signature: <base64 digest>
 *   x-webhook-timestamp: <unix milliseconds>
 * https://www.cashfree.com/docs/payments/online/webhooks/signature-verification
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
import { toEpochSeconds } from "../utils/timestamp.js";

export const cashfreeVerifier: ProviderVerifier = {
  name: "cashfree",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-webhook-signature"];
    const timestampStr = req.headers["x-webhook-timestamp"];

    if (!signature || !timestampStr) {
      return {
        valid: false,
        provider: "cashfree",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-webhook-signature" or "x-webhook-timestamp" header',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "cashfree",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-webhook-timestamp" format',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "cashfree",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToBase64(
      await computeHmacSha256(secret, `${timestampStr}${req.rawBody}`),
    );

    if (!timingSafeEqual(signature.trim(), expected)) {
      return {
        valid: false,
        provider: "cashfree",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "cashfree", timestamp };
  },
};
