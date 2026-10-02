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
    const signatures: string[] = [];

    const parts = signatureHeader.split(";");
    for (const part of parts) {
      const trimmed = part.trim();
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx !== -1) {
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed.slice(eqIdx + 1).trim();
        if (k === "ts" && v) timestampStr = v;
        // Multiple h= values are sent while a secret is being rotated.
        if (k === "h" && v) signatures.push(v.toLowerCase());
      }
    }

    if (!timestampStr || signatures.length === 0) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "paddle-signature" header format',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "paddle",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid timestamp format in "paddle-signature" header',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
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

    if (!signatures.some((sig) => timingSafeEqual(sig, expectedHex))) {
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
