import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const slackVerifier: ProviderVerifier = {
  name: "slack",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-slack-signature"];
    const timestampStr = req.headers["x-slack-request-timestamp"];

    if (!signature) {
      return {
        valid: false,
        provider: "slack",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-slack-signature" header',
      };
    }

    if (!timestampStr) {
      return {
        valid: false,
        provider: "slack",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-slack-request-timestamp" header',
      };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: "slack",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-slack-request-timestamp" format',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "slack",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const sigBasestring = `v0:${timestamp}:${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, sigBasestring);
    const expectedSig = `v0=${bytesToHex(hmacBytes)}`;

    if (!timingSafeEqual(signature.trim(), expectedSig)) {
      return {
        valid: false,
        provider: "slack",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "slack",
      timestamp,
    };
  },
};
