import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToHex } from '../utils/encoding.js';

export const linearVerifier: ProviderVerifier = {
  name: 'linear',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['linear-signature'];
    if (!signature) {
      return {
        valid: false,
        provider: 'linear',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "linear-signature" header',
      };
    }

    const expectedBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedHex = bytesToHex(expectedBytes);

    if (!timingSafeEqual(signature.trim(), expectedHex)) {
      return {
        valid: false,
        provider: 'linear',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'linear',
    };
  },
};
