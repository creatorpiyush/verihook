import { svixVerifier } from "./svix.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { bytesToHex } from "../utils/encoding.js";

import { toEpochSeconds } from "../utils/timestamp.js";

export const workosVerifier: ProviderVerifier = {
  name: "workos",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature =
      req.headers["workos-signature"] || req.headers["svix-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "workos",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "workos-signature" header',
      };
    }

    if (req.headers["svix-signature"]) {
      const svixRes = await svixVerifier.verify(req, secret, options);
      return { ...svixRes, provider: "workos" };
    }

    let timestampStr = "";
    const sigHexes: string[] = [];
    const parts = signature.split(",");
    for (const part of parts) {
      const trimmed = part.trim();
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx !== -1) {
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed.slice(eqIdx + 1).trim();
        if (k === "t" && v) timestampStr = v;
        // Multiple v1= values are sent while a secret is being rotated.
        if (k === "v1" && v) sigHexes.push(v.toLowerCase());
      }
    }

    if (!timestampStr || sigHexes.length === 0) {
      return {
        valid: false,
        provider: "workos",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "workos-signature" header format',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "workos",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid timestamp in "workos-signature" header',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "workos",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${timestampStr}.${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secret, payloadToSign);
    const expectedHex = bytesToHex(hmacBytes);

    if (!sigHexes.some((sig) => timingSafeEqual(sig, expectedHex))) {
      return {
        valid: false,
        provider: "workos",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "workos",
      timestamp,
    };
  },
};
