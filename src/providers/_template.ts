/**
 * Provider template — copy this file to `src/providers/<name>.ts` and follow
 * CONTRIBUTING.md ("Add a provider"). It is a working verifier for a fictional
 * "Acme" service, tested by `tests/provider-template.test.ts`, and is not
 * registered or shipped.
 *
 * Acme signs `<timestamp>.<raw body>` with HMAC-SHA256 and sends:
 *   x-acme-signature: <hex digest>
 *   x-acme-timestamp: <unix seconds>
 * Replace this description with a link to the provider's signature docs.
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

export const acmeVerifier: ProviderVerifier = {
  name: "acme",

  // Event name for `result.eventType`. Omit it if the body's `type`, `event` or
  // `event_type` field already holds the name.
  eventType: (event) => readString(event, "event_name"),

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    // Header names are lowercased by normalizeRequest().
    const signature = req.headers["x-acme-signature"];
    const timestampStr = req.headers["x-acme-timestamp"];

    if (!signature || !timestampStr) {
      return {
        valid: false,
        provider: "acme",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-acme-signature" or "x-acme-timestamp" header',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "acme",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-acme-timestamp" format',
      };
    }

    // Reject old requests (replay protection). Honour options.tolerance and options.now.
    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "acme",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    // Always sign req.rawBody (the exact bytes received), never a re-serialized object.
    const expected = bytesToHex(
      await computeHmacSha256(secret, `${timestampStr}.${req.rawBody}`),
    );

    // Compare with timingSafeEqual, never === .
    if (!timingSafeEqual(signature.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "acme",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "acme", timestamp };
  },
};
