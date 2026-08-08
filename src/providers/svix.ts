import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { base64ToBytes, bytesToBase64 } from "../utils/encoding.js";

export const svixVerifier: ProviderVerifier = {
  name: "svix",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const svixId = req.headers["svix-id"];
    const svixTimestamp = req.headers["svix-timestamp"];
    const svixSignature = req.headers["svix-signature"];

    if (!svixId || !svixTimestamp || !svixSignature) {
      return {
        valid: false,
        provider: "svix",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing required Svix headers ("svix-id", "svix-timestamp", or "svix-signature")',
      };
    }

    const timestamp = parseInt(svixTimestamp, 10);
    if (isNaN(timestamp)) {
      return {
        valid: false,
        provider: "svix",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "svix-timestamp" header format',
      };
    }

    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = options?.now ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "svix",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    let secretBytes: Uint8Array;
    if (secret.startsWith("whsec_")) {
      secretBytes = base64ToBytes(secret.slice(6));
    } else {
      try {
        secretBytes = base64ToBytes(secret);
      } catch {
        secretBytes = new TextEncoder().encode(secret);
      }
    }

    const payloadToSign = `${svixId}.${svixTimestamp}.${req.rawBody}`;
    const hmacBytes = await computeHmacSha256(secretBytes, payloadToSign);
    const expectedBase64 = bytesToBase64(hmacBytes);

    const signatures = svixSignature.split(" ").map((s) => s.trim());
    const valid = signatures.some((sig) => {
      const [version, b64] = sig.split(",");
      if (version === "v1" && b64) {
        return timingSafeEqual(b64, expectedBase64);
      }
      return false;
    });

    if (!valid) {
      return {
        valid: false,
        provider: "svix",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "svix",
      timestamp,
    };
  },
};
