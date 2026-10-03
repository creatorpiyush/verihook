/**
 * Mailgun webhooks.
 *
 * Mailgun puts the signature in the body, not a header:
 *   JSON webhooks: { "signature": { "timestamp", "token", "signature" }, "event-data": {...} }
 *   Form posts (routes / legacy webhooks): `timestamp`, `token`, `signature` fields
 * `signature` is the hex HMAC-SHA256 of `<timestamp><token>`, keyed with the HTTP
 * webhook signing key. It authenticates the sender but does not cover the event data.
 * Dedupe stores key on `token`, as Mailgun recommends.
 * https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { parseEvent, readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";
import { toEpochSeconds } from "../utils/timestamp.js";

/** The `{ timestamp, token, signature }` block from a JSON or form body. */
export function mailgunSignatureFields(
  event: unknown,
): { timestamp: string; token: string; signature: string } | undefined {
  const block =
    event && typeof event === "object" && "signature" in event
      ? typeof (event as Record<string, unknown>).signature === "object"
        ? (event as Record<string, unknown>).signature
        : event
      : undefined;
  const timestamp = readString(block, "timestamp");
  const token = readString(block, "token");
  const signature = readString(block, "signature");
  return timestamp && token && signature
    ? { timestamp, token, signature }
    : undefined;
}

export const mailgunVerifier: ProviderVerifier = {
  name: "mailgun",
  eventType: (event) =>
    readString(event, "event-data", "event") ?? readString(event, "event"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const fields = mailgunSignatureFields(parseEvent(req));
    if (!fields) {
      return {
        valid: false,
        provider: "mailgun",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          "Missing signature.timestamp, signature.token or signature.signature in the body",
      };
    }

    const rawTimestamp = parseInt(fields.timestamp, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "mailgun",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: "Invalid signature.timestamp format",
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "mailgun",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToHex(
      await computeHmacSha256(secret, `${fields.timestamp}${fields.token}`),
    );

    if (!timingSafeEqual(fields.signature.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "mailgun",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "mailgun", timestamp };
  },
};
