import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToBase64 } from '../utils/encoding.js';

export const shopifyVerifier: ProviderVerifier = {
  name: 'shopify',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signatureHeader = req.headers['x-shopify-hmac-sha256'];
    if (!signatureHeader) {
      return {
        valid: false,
        provider: 'shopify',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-shopify-hmac-sha256" header',
      };
    }

    const expectedBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedBase64 = bytesToBase64(expectedBytes);

    if (!timingSafeEqual(signatureHeader.trim(), expectedBase64)) {
      return {
        valid: false,
        provider: 'shopify',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'shopify',
    };
  },
};
