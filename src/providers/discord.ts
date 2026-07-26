import { verifyEd25519 } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';

export const discordVerifier: ProviderVerifier = {
  name: 'discord',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['x-signature-ed25519'];
    const timestampStr = req.headers['x-signature-timestamp'];

    if (!signature) {
      return {
        valid: false,
        provider: 'discord',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature-ed25519" header',
      };
    }

    if (!timestampStr) {
      return {
        valid: false,
        provider: 'discord',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature-timestamp" header',
      };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: 'discord',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-signature-timestamp" header format',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: 'discord',
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${timestampStr}${req.rawBody}`;
    const isValid = await verifyEd25519(secret, signature, payloadToSign);

    if (!isValid) {
      return {
        valid: false,
        provider: 'discord',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: 'Ed25519 signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'discord',
      timestamp,
    };
  },
};
