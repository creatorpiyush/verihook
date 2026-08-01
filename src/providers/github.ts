import { computeHmacSha1, computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToHex } from '../utils/encoding.js';

export const githubVerifier: ProviderVerifier = {
  name: 'github',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const sig256 = req.headers['x-hub-signature-256'];
    const sig1 = req.headers['x-hub-signature'];

    if (!sig256 && !sig1) {
      return {
        valid: false,
        provider: 'github',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-hub-signature-256" or "x-hub-signature" header',
      };
    }

    if (sig256) {
      const trimmed = sig256.trim();
      const cleanSig = trimmed.startsWith('sha256=') ? trimmed.slice(7) : trimmed;
      const expectedBytes = await computeHmacSha256(secret, req.rawBody);
      const expectedHex = bytesToHex(expectedBytes);

      if (!timingSafeEqual(cleanSig, expectedHex)) {
        return {
          valid: false,
          provider: 'github',
          code: WebhookErrorCode.INVALID_SIGNATURE,
          reason: 'SHA-256 signature mismatch',
        };
      }

      return {
        valid: true,
        provider: 'github',
      };
    }

    if (sig1) {
      const trimmed = sig1.trim();
      const cleanSig = trimmed.startsWith('sha1=') ? trimmed.slice(5) : trimmed;
      const expectedBytes = await computeHmacSha1(secret, req.rawBody);
      const expectedHex = bytesToHex(expectedBytes);

      if (!timingSafeEqual(cleanSig, expectedHex)) {
        return {
          valid: false,
          provider: 'github',
          code: WebhookErrorCode.INVALID_SIGNATURE,
          reason: 'SHA-1 signature mismatch',
        };
      }

      return {
        valid: true,
        provider: 'github',
      };
    }

    return {
      valid: false,
      provider: 'github',
      code: WebhookErrorCode.INVALID_SIGNATURE,
      reason: 'Invalid signature header',
    };
  },
};
