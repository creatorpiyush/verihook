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
      const cleanSig = sig256.startsWith('sha256=') ? sig256.slice(7) : sig256;
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
      const cleanSig = sig1.startsWith('sha1=') ? sig1.slice(5) : sig1;
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
