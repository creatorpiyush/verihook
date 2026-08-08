import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const pagerdutyVerifier: ProviderVerifier = {
  name: "pagerduty",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signatureHeader = req.headers["x-pagerduty-signature"];
    if (!signatureHeader) {
      return {
        valid: false,
        provider: "pagerduty",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-pagerduty-signature" header',
      };
    }

    const signatures = signatureHeader.split(",").map((s) => s.trim());
    const hmacBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedHex = bytesToHex(hmacBytes);

    const valid = signatures.some((sig) => {
      const cleanSig = sig.startsWith("v1=") ? sig.slice(3) : sig;
      return timingSafeEqual(cleanSig.toLowerCase(), expectedHex.toLowerCase());
    });

    if (!valid) {
      return {
        valid: false,
        provider: "pagerduty",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "pagerduty",
    };
  },
};
