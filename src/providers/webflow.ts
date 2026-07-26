import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToHex } from '../utils/encoding.js';

export const webflowVerifier: ProviderVerifier = {
  name: 'webflow',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['x-webflow-signature'];
    if (!signature) {
      return {
        valid: false,
        provider: 'webflow',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-webflow-signature" header',
      };
    }

    const timestampStr = req.headers['x-webflow-timestamp'];
    let timestamp: number | undefined;

    if (timestampStr) {
      timestamp = parseInt(timestampStr, 10);
      const tolerance = options?.tolerance ?? 300;
      if (!isNaN(timestamp) && tolerance > 0) {
        const now = options?.now ?? Math.floor(Date.now() / 1000);
        if (Math.abs(now - timestamp) > tolerance) {
          return {
            valid: false,
            provider: 'webflow',
            code: WebhookErrorCode.EXPIRED_TIMESTAMP,
            timestamp,
            reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
          };
        }
      }
    }

    const payloadToSign = timestampStr ? `${timestampStr}:${req.rawBody}` : req.rawBody;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedHex = bytesToHex(hmacBytes);

    const cleanSig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
    if (!timingSafeEqual(cleanSig.trim().toLowerCase(), expectedHex.toLowerCase())) {
      return {
        valid: false,
        provider: 'webflow',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'webflow',
      timestamp,
    };
  },
};
