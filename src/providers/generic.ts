import { computeHmac, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToBase64, bytesToHex } from '../utils/encoding.js';

export const genericVerifier: ProviderVerifier = {
  name: 'generic',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const headerName = options?.headerName?.toLowerCase() || 'x-signature';
    const signature = req.headers[headerName];

    if (!signature) {
      return {
        valid: false,
        provider: 'generic',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: `Missing signature header "${headerName}"`,
      };
    }

    const algorithmName = options?.algorithm ?? 'sha256';
    const encoding = options?.encoding ?? 'hex';

    let alg: 'SHA-256' | 'SHA-1' | 'SHA-512' = 'SHA-256';
    if (algorithmName === 'sha1') alg = 'SHA-1';
    if (algorithmName === 'sha512') alg = 'SHA-512';

    const hmacBytes = await computeHmac(alg, secret, req.rawBody);
    let expectedSig = '';

    if (encoding === 'hex') {
      expectedSig = bytesToHex(hmacBytes);
    } else if (encoding === 'base64') {
      expectedSig = bytesToBase64(hmacBytes);
    } else if (encoding === 'prefix-hex') {
      expectedSig = `${algorithmName}=${bytesToHex(hmacBytes)}`;
    }

    let cleanSignature = signature.trim();
    if (encoding === 'prefix-hex' && !cleanSignature.includes('=')) {
      cleanSignature = `${algorithmName}=${cleanSignature}`;
    }

    if (!timingSafeEqual(cleanSignature, expectedSig)) {
      return {
        valid: false,
        provider: 'generic',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'generic',
    };
  },
};
