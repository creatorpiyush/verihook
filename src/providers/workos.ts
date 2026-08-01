import { svixVerifier } from './svix.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { bytesToHex } from '../utils/encoding.js';

export const workosVerifier: ProviderVerifier = {
  name: 'workos',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['workos-signature'] || req.headers['svix-signature'];
    if (!signature) {
      return {
        valid: false,
        provider: 'workos',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "workos-signature" header',
      };
    }

    if (req.headers['svix-signature']) {
      const svixRes = await svixVerifier.verify(req, secret, options);
      return { ...svixRes, provider: 'workos' };
    }

    let timestampStr = '';
    let sigHex = '';
    const parts = signature.split(',');
    for (const part of parts) {
      const [k, v] = part.split('=');
      if (k && k.trim() === 't' && v) timestampStr = v.trim();
      if (k && k.trim() === 'v1' && v) sigHex = v.trim();
    }

    if (!timestampStr || !sigHex) {
      return {
        valid: false,
        provider: 'workos',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "workos-signature" header format',
      };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: 'workos',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid timestamp in "workos-signature" header',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: 'workos',
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${timestampStr}.${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedHex = bytesToHex(hmacBytes);

    if (!timingSafeEqual(sigHex.toLowerCase(), expectedHex.toLowerCase())) {
      return {
        valid: false,
        provider: 'workos',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'workos',
      timestamp,
    };
  },
};
