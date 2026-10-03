/**
 * Bitbucket Cloud and Bitbucket Data Center webhooks.
 *
 * Bitbucket signs the raw body with HMAC-SHA256, keyed with the webhook secret, and
 * sends the hex digest:
 *   X-Hub-Signature: sha256=<hex digest>
 * The event name is in `X-Event-Key` (e.g. `repo:push`).
 * https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/
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

export const bitbucketVerifier: ProviderVerifier = {
  name: "bitbucket",
  eventType: (_event, req) => req.headers["x-event-key"],
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["x-hub-signature"];
    if (!header) {
      return {
        valid: false,
        provider: "bitbucket",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-hub-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha256(secret, req.rawBody));
    const signature = header
      .trim()
      .replace(/^sha256=/i, "")
      .toLowerCase();

    if (!timingSafeEqual(signature, expected)) {
      return {
        valid: false,
        provider: "bitbucket",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "bitbucket" };
  },
};
