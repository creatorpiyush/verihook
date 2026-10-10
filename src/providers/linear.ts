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

export const linearVerifier: ProviderVerifier = {
  name: "linear",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["linear-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "linear",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "linear-signature" header',
      };
    }

    const expectedBytes = await computeHmacSha256(secret, req.rawBody);
    const expectedHex = bytesToHex(expectedBytes);

    if (!timingSafeEqual(signature.trim(), expectedHex)) {
      return {
        valid: false,
        provider: "linear",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    // `webhookTimestamp` (Unix ms) is in the signed body, so it can't be stripped
    // from a real delivery. Linear recommends rejecting anything older than a minute.
    let rawTimestamp: unknown;
    try {
      rawTimestamp = JSON.parse(req.rawBody)?.webhookTimestamp;
    } catch {
      rawTimestamp = undefined;
    }
    if (typeof rawTimestamp !== "number" || !Number.isFinite(rawTimestamp)) {
      return { valid: true, provider: "linear" };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 60;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "linear",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (webhookTimestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    return { valid: true, provider: "linear", timestamp };
  },
};
