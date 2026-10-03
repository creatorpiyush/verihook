/**
 * Postmark webhooks.
 *
 * Postmark doesn't sign webhooks. Protect the endpoint with HTTP Basic auth by adding
 * credentials to the webhook URL (`https://user:pass@example.com/webhooks/postmark`);
 * Postmark then sends:
 *   Authorization: Basic <base64("user:pass")>
 * Pass `"user:pass"` as the secret. Postmark also recommends allowlisting its IPs.
 * https://postmarkapp.com/developer/webhooks/webhooks-overview
 */
import { timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64, stringToBytes } from "../utils/encoding.js";

export const postmarkVerifier: ProviderVerifier = {
  name: "postmark",
  eventType: (event) => readString(event, "RecordType"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    if (!secret.includes(":")) {
      return {
        valid: false,
        provider: "postmark",
        code: WebhookErrorCode.INVALID_SECRET,
        reason:
          'Postmark secret must be the Basic auth credentials as "username:password"',
      };
    }

    const authorization = req.headers["authorization"];
    const match = authorization?.trim().match(/^basic\s+(\S+)$/i);
    if (!match) {
      return {
        valid: false,
        provider: "postmark",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing Basic "authorization" header (add user:pass@ to the webhook URL in Postmark)',
      };
    }

    if (!timingSafeEqual(match[1], bytesToBase64(stringToBytes(secret)))) {
      return {
        valid: false,
        provider: "postmark",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Basic auth credentials mismatch",
      };
    }

    return { valid: true, provider: "postmark" };
  },
};
