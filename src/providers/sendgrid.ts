/**
 * Twilio SendGrid signed Event Webhook.
 *
 * SendGrid signs `<timestamp><raw body>` with ECDSA (P-256, SHA-256) and sends:
 *   X-Twilio-Email-Event-Webhook-Signature: <base64 DER signature>
 *   X-Twilio-Email-Event-Webhook-Timestamp: <unix seconds>
 * The secret is the verification key from Mail Settings > Event Webhook (base64,
 * or a PEM "PUBLIC KEY" block).
 * https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features
 */
import { verifyEcdsaP256Sha256 } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { toEpochSeconds } from "../utils/timestamp.js";

export const sendgridVerifier: ProviderVerifier = {
  name: "sendgrid",
  // The body is a batch of events; this is the first one's `event`.
  eventType: (event) =>
    Array.isArray(event) ? readString(event[0], "event") : undefined,
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-twilio-email-event-webhook-signature"];
    const timestampStr = req.headers["x-twilio-email-event-webhook-timestamp"];

    if (!signature || !timestampStr) {
      return {
        valid: false,
        provider: "sendgrid",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "x-twilio-email-event-webhook-signature" or "x-twilio-email-event-webhook-timestamp" header (enable Signed Event Webhook)',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "sendgrid",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-twilio-email-event-webhook-timestamp" format',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "sendgrid",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const valid = await verifyEcdsaP256Sha256(
      secret,
      signature,
      `${timestampStr}${req.rawBody}`,
    );
    if (!valid) {
      return {
        valid: false,
        provider: "sendgrid",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason:
          "Signature mismatch (or the verification key is not a P-256 public key)",
      };
    }

    return { valid: true, provider: "sendgrid", timestamp };
  },
};
