/**
 * PhonePe Payment Gateway (India) webhooks.
 *
 * PhonePe authenticates webhooks with the username and password configured for the
 * webhook in the PhonePe dashboard. It sends the lowercase hex SHA-256 of
 * `<username>:<password>`:
 *   Authorization: <hex sha256("username:password")>
 * Pass `"username:password"` as the secret. The body itself is not signed, so treat
 * the payload as a notification and confirm the order status with PhonePe's API
 * before fulfilling it.
 * https://developer.phonepe.com/payment-gateway/website-integration/standard-checkout/api-integration/api-reference/webhook
 */
import { computeSha256, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const phonepeVerifier: ProviderVerifier = {
  name: "phonepe",

  // `type` is deprecated in PhonePe's v2 payloads; `event` holds the event name.
  eventType: (event) => readString(event, "event") ?? readString(event, "type"),

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const authorization = req.headers["authorization"];
    if (!authorization) {
      return {
        valid: false,
        provider: "phonepe",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "authorization" header',
      };
    }

    if (!secret.includes(":")) {
      return {
        valid: false,
        provider: "phonepe",
        code: WebhookErrorCode.INVALID_SECRET,
        reason:
          'PhonePe secret must be the webhook credentials as "username:password"',
      };
    }

    const expected = bytesToHex(await computeSha256(secret));
    const received = authorization
      .trim()
      .replace(/^sha256\s+/i, "")
      .toLowerCase();

    if (!timingSafeEqual(received, expected)) {
      return {
        valid: false,
        provider: "phonepe",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Authorization hash mismatch",
      };
    }

    return { valid: true, provider: "phonepe" };
  },
};
