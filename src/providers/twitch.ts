/**
 * Twitch EventSub webhooks.
 *
 * Twitch signs `<message id><timestamp><raw body>` with HMAC-SHA256, keyed with the
 * subscription secret, and sends:
 *   Twitch-Eventsub-Message-Signature: sha256=<hex digest>
 *   Twitch-Eventsub-Message-Id: <id>
 *   Twitch-Eventsub-Message-Timestamp: <RFC 3339, e.g. 2023-07-19T14:56:51.634234626Z>
 * Twitch asks you to reject messages older than 10 minutes, so the default
 * tolerance here is 600 s. Answer `webhook_callback_verification` messages
 * (`Twitch-Eventsub-Message-Type`) with `event.challenge` as text/plain.
 * https://dev.twitch.tv/docs/eventsub/handling-webhook-events/
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

/** Parses an RFC 3339 timestamp to Unix seconds (sub-millisecond digits are dropped). */
function parseRfc3339(value: string): number {
  const ms = Date.parse(value.trim().replace(/(\.\d{3})\d+/, "$1"));
  return isNaN(ms) ? NaN : Math.floor(ms / 1000);
}

export const twitchVerifier: ProviderVerifier = {
  name: "twitch",
  eventType: (event, req) =>
    req.headers["twitch-eventsub-subscription-type"] ??
    readString(event, "subscription", "type"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["twitch-eventsub-message-signature"];
    const messageId = req.headers["twitch-eventsub-message-id"];
    const timestampStr = req.headers["twitch-eventsub-message-timestamp"];

    if (!header || !messageId || !timestampStr) {
      return {
        valid: false,
        provider: "twitch",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "twitch-eventsub-message-signature", "twitch-eventsub-message-id" or "twitch-eventsub-message-timestamp" header',
      };
    }

    const timestamp = parseRfc3339(timestampStr);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: "twitch",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "twitch-eventsub-message-timestamp" format',
      };
    }

    const tolerance = options?.tolerance ?? 600;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "twitch",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToHex(
      await computeHmacSha256(
        secret,
        `${messageId}${timestampStr}${req.rawBody}`,
      ),
    );
    const signature = header
      .trim()
      .replace(/^sha256=/i, "")
      .toLowerCase();

    if (!timingSafeEqual(signature, expected)) {
      return {
        valid: false,
        provider: "twitch",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "twitch", timestamp };
  },
};
