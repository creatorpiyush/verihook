/**
 * Recurly (USA) JSON webhooks.
 *
 * Recurly signs `<timestamp>.<raw body>` with HMAC-SHA256, keyed with the endpoint's
 * secret, and sends the timestamp followed by one or more hex digests (two during a
 * 24-hour key rotation; either may match):
 *   recurly-signature: <unix milliseconds>,<hex digest>[,<hex digest>]
 * XML webhooks are not signed.
 * https://docs.recurly.com/recurly-subscriptions/docs/signature-verification
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";
import { toEpochSeconds } from "../utils/timestamp.js";

export const recurlyVerifier: ProviderVerifier = {
  name: "recurly",

  // e.g. "subscription.created" from `object_type` + `event_type`.
  eventType: (event) => {
    const eventType = readString(event, "event_type");
    const objectType = readString(event, "object_type");
    return eventType && objectType ? `${objectType}.${eventType}` : eventType;
  },

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["recurly-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "recurly",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "recurly-signature" header',
      };
    }

    const [timestampStr, ...signatures] = header
      .split(",")
      .map((part) => part.trim());
    const rawTimestamp = Number(timestampStr);
    if (!timestampStr || !Number.isInteger(rawTimestamp) || !signatures[0]) {
      return {
        valid: false,
        provider: "recurly",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "recurly-signature" header format',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "recurly",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToHex(
      await computeHmacSha256(secret, `${timestampStr}.${req.rawBody}`),
    );

    if (
      !signatures.some((sig) => timingSafeEqual(sig.toLowerCase(), expected))
    ) {
      return {
        valid: false,
        provider: "recurly",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "recurly", timestamp };
  },
};
