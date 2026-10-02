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
import { resolveSignedUrl, toggleDefaultPort } from "../utils/request-url.js";

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

    const url = resolveSignedUrl(req, options?.url);
    if (!url) {
      return {
        valid: false,
        provider: "twilio",
        code: WebhookErrorCode.MISSING_URL,
        reason:
          "Missing request URL. Provide request URL or pass options.url explicitly for Twilio verification",
      };
    }

    const contentType = (req.headers["content-type"] || "").toLowerCase();
    const hasExplicitFormContentType = contentType.includes(
      "application/x-www-form-urlencoded",
    );
    const hasMissingContentType = !contentType;
    const looksLikeFormBody = /(^|&)[^=&]+=[^&]*/.test(req.rawBody);
    const isFormUrlEncoded =
      hasExplicitFormContentType ||
      (hasMissingContentType && looksLikeFormBody);

    let bodyHashHex: string | undefined;
    if (!isFormUrlEncoded && req.rawBody) {
      bodyHashHex = bytesToHex(await computeSha256(req.rawBody)).toLowerCase();
    }

    const buildDataToSign = (signedUrl: string): string => {
      if (isFormUrlEncoded && req.rawBody) {
        // Standard Twilio Form signature: URL + sorted key/value parameters
        let data = signedUrl;
        const params = new URLSearchParams(req.rawBody);
        const sortedKeys = Array.from(new Set(params.keys())).sort();
        for (const key of sortedKeys) {
          for (const val of params.getAll(key)) {
            data += key + val;
          }
        }
        return data;
      }
      if (bodyHashHex) {
        // Twilio JSON / Non-form signature: exact URL with bodySHA256 parameter.
        // Edited textually: re-serializing via URL() can alter the signed string.
        const bodyShaRegex = /([?&])bodySHA256=[^&#]*/i;
        if (bodyShaRegex.test(signedUrl)) {
          return signedUrl.replace(bodyShaRegex, `$1bodySHA256=${bodyHashHex}`);
        }
        const delimiter = signedUrl.includes("?") ? "&" : "?";
        return `${signedUrl}${delimiter}bodySHA256=${bodyHashHex}`;
      }
      return signedUrl;
    };

    const candidateUrls = [url];
    const portVariant = toggleDefaultPort(url);
    if (portVariant) candidateUrls.push(portVariant);

    let isValid = false;
    for (const candidate of candidateUrls) {
      const hmacBytes = await computeHmacSha1(
        secret,
        buildDataToSign(candidate),
      );
      if (timingSafeEqual(signature.trim(), bytesToBase64(hmacBytes))) {
        isValid = true;
      }
    }

    if (!isValid) {
      return {
        valid: false,
        provider: "twilio",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: `Signature mismatch (signed URL: ${url})`,
      };
    }

    return {
      valid: true,
      provider: "twilio",
    };
  },
};
