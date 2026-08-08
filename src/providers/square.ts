import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64 } from "../utils/encoding.js";

export const squareVerifier: ProviderVerifier = {
  name: "square",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-square-hmacsha256-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "square",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-square-hmacsha256-signature" header',
      };
    }

    const url = options?.url || req.url;
    if (!url) {
      return {
        valid: false,
        provider: "square",
        code: WebhookErrorCode.MISSING_URL,
        reason:
          "Missing request URL. Provide request URL or pass options.url explicitly for Square verification",
      };
    }

    const payloadToSign = url + req.rawBody;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedBase64 = bytesToBase64(hmacBytes);

    if (!timingSafeEqual(signature.trim(), expectedBase64)) {
      return {
        valid: false,
        provider: "square",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "square",
    };
  },
};
