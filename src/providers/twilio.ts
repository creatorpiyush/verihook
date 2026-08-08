import {
  computeHmacSha1,
  computeSha256,
  timingSafeEqual,
} from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64, bytesToHex } from "../utils/encoding.js";

export const twilioVerifier: ProviderVerifier = {
  name: "twilio",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-twilio-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "twilio",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-twilio-signature" header',
      };
    }

    const url = options?.url || req.url;
    if (!url) {
      return {
        valid: false,
        provider: "twilio",
        code: WebhookErrorCode.MISSING_URL,
        reason:
          "Missing request URL. Provide request URL or pass options.url explicitly for Twilio verification",
      };
    }

    let dataToSign = url;
    const contentType = (req.headers["content-type"] || "").toLowerCase();

    const hasExplicitFormContentType = contentType.includes(
      "application/x-www-form-urlencoded",
    );
    const hasMissingContentType = !contentType;
    const looksLikeFormBody = /(^|&)[^=&]+=[^&]*/.test(req.rawBody);
    const isFormUrlEncoded =
      hasExplicitFormContentType ||
      (hasMissingContentType && looksLikeFormBody);

    if (isFormUrlEncoded && req.rawBody) {
      // Standard Twilio Form signature: URL + sorted key/value parameters
      const params = new URLSearchParams(req.rawBody);
      const sortedKeys = Array.from(new Set(params.keys())).sort();

      for (const key of sortedKeys) {
        const values = params.getAll(key);
        for (const val of values) {
          dataToSign += key + val;
        }
      }
    } else if (req.rawBody) {
      // Twilio JSON / Non-form signature: URL + bodySHA256 parameter
      const bodyHashBytes = await computeSha256(req.rawBody);
      const bodyHashHex = bytesToHex(bodyHashBytes).toLowerCase();

      // Replace existing bodySHA256 if present instead of appending duplicates.
      try {
        const parsedUrl = new URL(url);
        parsedUrl.searchParams.set("bodySHA256", bodyHashHex);
        dataToSign = parsedUrl.toString();
      } catch {
        const hasQuery = url.includes("?");
        const bodyShaRegex = /([?&])bodySHA256=[^&]*/i;
        if (bodyShaRegex.test(url)) {
          dataToSign = url.replace(
            bodyShaRegex,
            `$1bodySHA256=${encodeURIComponent(bodyHashHex)}`,
          );
        } else {
          const delimiter = hasQuery ? "&" : "?";
          dataToSign = `${url}${delimiter}bodySHA256=${encodeURIComponent(bodyHashHex)}`;
        }
      }
    }

    const hmacBytes = await computeHmacSha1(secret, dataToSign);
    const expectedBase64 = bytesToBase64(hmacBytes);

    if (!timingSafeEqual(signature.trim(), expectedBase64)) {
      return {
        valid: false,
        provider: "twilio",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "twilio",
    };
  },
};
