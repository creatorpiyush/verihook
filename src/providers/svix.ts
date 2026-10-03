import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { base64ToBytes, bytesToBase64 } from "../utils/encoding.js";

import { toEpochSeconds } from "../utils/timestamp.js";

/**
 * Verifies a Svix / Standard Webhooks signature: `v1,<base64>` HMAC-SHA256 of
 * `<id>.<timestamp>.<body>`, keyed with the base64 secret (`whsec_` prefix optional).
 * `prefix` picks the header family: `svix-*` or Standard Webhooks' `webhook-*`.
 */
export async function verifySvixStyle(
  provider: string,
  prefix: "svix" | "webhook",
  req: NormalizedWebhookRequest,
  secret: string,
  options?: VerifyWebhookOptions,
): Promise<VerificationResult> {
  const svixId = req.headers[`${prefix}-id`];
  const svixTimestamp = req.headers[`${prefix}-timestamp`];
  const svixSignature = req.headers[`${prefix}-signature`];

  if (!svixId || !svixTimestamp || !svixSignature) {
    return {
      valid: false,
      provider,
      code: WebhookErrorCode.MISSING_HEADER,
      reason: `Missing required ${prefix === "svix" ? "Svix" : "Standard Webhooks"} headers ("${prefix}-id", "${prefix}-timestamp", or "${prefix}-signature")`,
    };
  }

  const rawTimestamp = parseInt(svixTimestamp, 10);
  if (isNaN(rawTimestamp)) {
    return {
      valid: false,
      provider,
      code: WebhookErrorCode.MISSING_HEADER,
      reason: `Invalid "${prefix}-timestamp" header format`,
    };
  }

  const timestamp = toEpochSeconds(rawTimestamp);
  const tolerance = options?.tolerance ?? 300;
  if (tolerance > 0) {
    const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
    if (Math.abs(now - timestamp) > tolerance) {
      return {
        valid: false,
        provider,
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
    const commaIdx = sig.indexOf(",");
    if (commaIdx !== -1) {
      const version = sig.slice(0, commaIdx);
      const b64 = sig.slice(commaIdx + 1);
      if (version === "v1" && b64) {
        return timingSafeEqual(b64, expectedBase64);
      }
    }
    return false;
  });

  if (!valid) {
    return {
      valid: false,
      provider,
      code: WebhookErrorCode.INVALID_SIGNATURE,
      timestamp,
      reason: "Signature mismatch",
    };
  }

  return { valid: true, provider, timestamp };
}

export const svixVerifier: ProviderVerifier = {
  name: "svix",
  verify: (req, secret, options) =>
    verifySvixStyle("svix", "svix", req, secret, options),
};
