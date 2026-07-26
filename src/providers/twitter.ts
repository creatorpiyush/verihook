import { computeHmacSha256, timingSafeEqual } from '../core/crypto.js';
import { NormalizedWebhookRequest, ProviderVerifier, VerificationResult, VerifyWebhookOptions, WebhookErrorCode } from '../core/types.js';
import { bytesToBase64 } from '../utils/encoding.js';

export const twitterVerifier: ProviderVerifier = {
  name: 'twitter',
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions
  ): Promise<VerificationResult> {
    const signature = req.headers['x-twitter-webhooks-signature'];
    if (!signature) {
      return {
        valid: false,
        provider: 'twitter',
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-twitter-webhooks-signature" header',
      };
    }

    const cleanSig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
    const hmacBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedBase64 = bytesToBase64(hmacBytes);

    if (!timingSafeEqual(cleanSig.trim(), expectedBase64)) {
      return {
        valid: false,
        provider: 'twitter',
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: 'Signature mismatch',
      };
    }

    return {
      valid: true,
      provider: 'twitter',
    };
  },
};

export interface TwitterCrcResponse {
  response_token: string;
}

/**
 * Calculates the required CRC response token for Twitter / X Account Activity API challenge handshake.
 *
 * @param crcToken The crc_token query parameter sent by Twitter in GET request.
 * @param consumerSecret Twitter / X App Consumer Secret.
 */
export async function verifyTwitterCrc(
  crcToken: string,
  consumerSecret: string
): Promise<TwitterCrcResponse> {
  const hmacBytes = await computeHmacSha256(consumerSecret, crcToken);
  const base64Digest = bytesToBase64(hmacBytes);
  return {
    response_token: `sha256=${base64Digest}`,
  };
}

export const verifyXCrc = verifyTwitterCrc;
