import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToHex } from '../utils/encoding.js';

export const lemonsqueezyVerifier: ProviderVerifier = {
  name: 'lemonsqueezy',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['x-signature'];
    if (!signature) {
      return {
        valid: false,
        provider: 'lemonsqueezy',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature" header',
      };
    }

    const hmacBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedHex = bytesToHex(hmacBytes);

    if (!timingSafeEqual(signature.trim().toLowerCase(), expectedHex.toLowerCase())) {
      return {
        valid: false,
        provider: 'lemonsqueezy',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'lemonsqueezy',
    };
  },
};
