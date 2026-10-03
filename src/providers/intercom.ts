/**
 * Intercom webhooks.
 *
 * Intercom signs the raw body with HMAC-SHA1, keyed with the app's client secret,
 * and sends the hex digest:
 *   X-Hub-Signature: sha1=<hex digest>
 * https://developers.intercom.com/docs/references/2.7/rest-api/webhooks/webhook-models
 */
import { computeHmacSha1, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const intercomVerifier: ProviderVerifier = {
  name: "intercom",
  eventType: (event) => readString(event, "topic"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["x-hub-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "intercom",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-hub-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha1(secret, req.rawBody));
    const signature = header
      .trim()
      .replace(/^sha1=/i, "")
      .toLowerCase();

    if (!timingSafeEqual(signature, expected)) {
      return {
        valid: false,
        provider: "intercom",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "intercom" };
  },
};
