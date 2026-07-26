import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToHex } from '../utils/encoding.js';

export const zoomVerifier: ProviderVerifier = {
  name: 'zoom',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['x-zm-signature'];
    const timestampStr = req.headers['x-zm-request-timestamp'];

    if (!signature) {
      return {
        valid: false,
        provider: 'zoom',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-zm-signature" header',
      };
    }

    if (!timestampStr) {
      return {
        valid: false,
        provider: 'zoom',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-zm-request-timestamp" header',
      };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: 'zoom',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-zm-request-timestamp" header format',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: 'zoom',
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const message = `v0:${timestamp}:${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, message);
    const expectedHex = `v0=${bytesToHex(hmacBytes)}`;

    if (!timingSafeEqual(signature.trim(), expectedHex)) {
      return {
        valid: false,
        provider: 'zoom',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'zoom',
      timestamp,
    };
  },
};
