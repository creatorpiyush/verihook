/**
 * Vercel webhooks (account, team and integration webhooks, and log drains).
 *
 * Vercel signs the raw body with HMAC-SHA1, keyed with the webhook secret (or the
 * integration's client secret), and sends the hex digest:
 *   x-vercel-signature: <hex digest>
 * https://vercel.com/docs/webhooks
 */
import { computeHmacSha1, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const vercelVerifier: ProviderVerifier = {
  name: "vercel",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-vercel-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "vercel",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-vercel-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha1(secret, req.rawBody));

    if (!timingSafeEqual(signature.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "vercel",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "vercel" };
  },
};
