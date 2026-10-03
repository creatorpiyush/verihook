/**
 * Sentry integration platform webhooks.
 *
 * Sentry signs the raw body with HMAC-SHA256, keyed with the integration's client
 * secret, and sends the hex digest:
 *   Sentry-Hook-Signature: <hex digest>
 * The resource is in `Sentry-Hook-Resource` and the action in the body, so
 * `result.eventType` is e.g. `issue.created`.
 * https://docs.sentry.io/organization/integrations/integration-platform/webhooks/
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

export const sentryVerifier: ProviderVerifier = {
  name: "sentry",
  eventType: (event, req) => {
    const resource = req.headers["sentry-hook-resource"];
    const action = readString(event, "action");
    return resource && action ? `${resource}.${action}` : resource || action;
  },
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["sentry-hook-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "sentry",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "sentry-hook-signature" header',
      };
    }

    const expected = bytesToHex(await computeHmacSha256(secret, req.rawBody));

    if (!timingSafeEqual(signature.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "sentry",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "sentry" };
  },
};
