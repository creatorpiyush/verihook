/**
 * Calendly webhooks.
 *
 * Calendly signs `<t>.<raw body>` with HMAC-SHA256, keyed with the webhook
 * subscription's signing key, and sends:
 *   Calendly-Webhook-Signature: t=<unix seconds>,v1=<hex digest>
 * Calendly's guide rejects signatures older than 3 minutes, so the default
 * tolerance here is 180 s.
 * https://developer.calendly.com/api-docs/overview/webhooks/webhook-signatures
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
import { toEpochSeconds } from "../utils/timestamp.js";

export const calendlyVerifier: ProviderVerifier = {
  name: "calendly",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["calendly-webhook-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "calendly",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "calendly-webhook-signature" header',
      };
    }

    let timestampStr: string | undefined;
    const signatures: string[] = [];
    for (const part of header.split(",")) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      const key = part.slice(0, eq).trim();
      const value = part.slice(eq + 1).trim();
      if (key === "t") timestampStr = value;
      if (key === "v1" && value) signatures.push(value.toLowerCase());
    }

    const rawTimestamp = Number(timestampStr);
    if (
      !timestampStr ||
      !Number.isInteger(rawTimestamp) ||
      !signatures.length
    ) {
      return {
        valid: false,
        provider: "calendly",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "calendly-webhook-signature" header format',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 180;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "calendly",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToHex(
      await computeHmacSha256(secret, `${timestampStr}.${req.rawBody}`),
    );

    if (!signatures.some((sig) => timingSafeEqual(sig, expected))) {
      return {
        valid: false,
        provider: "calendly",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "calendly", timestamp };
  },
};
