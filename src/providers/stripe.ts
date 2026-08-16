import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

import { toEpochSeconds } from "../utils/timestamp.js";

export const stripeVerifier: ProviderVerifier = {
  name: "stripe",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signatureHeader = req.headers["stripe-signature"];
    if (!signatureHeader) {
      return {
        valid: false,
        provider: "stripe",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "stripe-signature" header',
      };
    }

    const parts = signatureHeader.split(",");
    let rawTimestamp: number | undefined;
    const signatures: string[] = [];

    for (const part of parts) {
      const trimmed = part.trim();
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx !== -1) {
        const key = trimmed.slice(0, eqIdx);
        const value = trimmed.slice(eqIdx + 1);
        if (key === "t") {
          rawTimestamp = parseInt(value, 10);
        } else if (key === "v1" && value) {
          signatures.push(value);
        }
      }
    }

    if (rawTimestamp === undefined || isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "stripe",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "stripe-signature" header format: timestamp missing',
      };
    }

    if (signatures.length === 0) {
      return {
        valid: false,
        provider: "stripe",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Invalid "stripe-signature" header format: v1 signature missing',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "stripe",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (signature timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${rawTimestamp}.${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedHex = bytesToHex(hmacBytes);

    const isValid = signatures.some((sig) => timingSafeEqual(sig, expectedHex));

    if (!isValid) {
      return {
        valid: false,
        provider: "stripe",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "stripe",
      timestamp,
    };
  },
};
