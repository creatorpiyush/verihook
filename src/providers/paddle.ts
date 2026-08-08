import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const paddleVerifier: ProviderVerifier = {
  name: "paddle",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signatureHeader = req.headers["paddle-signature"];
    if (!signatureHeader) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "paddle-signature" header',
      };
    }

    let timestampStr = "";
    let signature = "";

    const parts = signatureHeader.split(";");
    for (const part of parts) {
      const [k, v] = part.split("=");
      if (k && k.trim() === "ts" && v) timestampStr = v.trim();
      if (k && k.trim() === "h" && v) signature = v.trim();
    }

    if (!timestampStr || !signature) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "paddle-signature" header format',
      };
    }

    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid timestamp format in "paddle-signature" header',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "paddle",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${timestampStr}:${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedHex = bytesToHex(hmacBytes);

    if (
      !timingSafeEqual(
        signature.trim().toLowerCase(),
        expectedHex.toLowerCase(),
      )
    ) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "paddle",
      timestamp,
    };
  },
};
