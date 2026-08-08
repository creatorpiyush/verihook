import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const razorpayVerifier: ProviderVerifier = {
  name: "razorpay",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-razorpay-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "razorpay",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-razorpay-signature" header',
      };
    }

    const expectedBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedHex = bytesToHex(expectedBytes);

    if (!timingSafeEqual(signature.trim(), expectedHex)) {
      return {
        valid: false,
        provider: "razorpay",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "razorpay",
    };
  },
};
