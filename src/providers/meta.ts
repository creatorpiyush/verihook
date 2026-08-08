import {
  computeHmacSha1,
  computeHmacSha256,
  timingSafeEqual,
} from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

export const metaVerifier: ProviderVerifier = {
  name: "meta",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const sig256 = req.headers["x-hub-signature-256"];
    const sig1 = req.headers["x-hub-signature"];

    if (!sig256 && !sig1) {
      return {
        valid: false,
        provider: "meta",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-hub-signature-256" or "x-hub-signature" header',
      };
    }

    if (sig256) {
      const cleanSig256 = sig256.startsWith("sha256=")
        ? sig256.slice(7)
        : sig256;
      const hmac256 = await computeHmacSha256(secret, req.rawBody);
      const expected256 = bytesToHex(hmac256);
      if (
        timingSafeEqual(
          cleanSig256.trim().toLowerCase(),
          expected256.toLowerCase(),
        )
      ) {
        return {
          valid: true,
          provider: "meta",
        };
      }
    }

    if (sig1) {
      const cleanSig1 = sig1.startsWith("sha1=") ? sig1.slice(5) : sig1;
      const hmac1 = await computeHmacSha1(secret, req.rawBody);
      const expected1 = bytesToHex(hmac1);
      if (
        timingSafeEqual(cleanSig1.trim().toLowerCase(), expected1.toLowerCase())
      ) {
        return {
          valid: true,
          provider: "meta",
        };
      }
    }

    return {
      valid: false,
      provider: "meta",
      code: WebhookErrorCode.INVALID_SIGNATURE,
      reason: "Signature mismatch",
    };
  },
};

export interface MetaChallengeQueryParams {
  "hub.mode"?: string;
  "hub.challenge"?: string;
  "hub.verify_token"?: string;
  [key: string]: string | undefined;
}

export interface MetaChallengeResult {
  valid: boolean;
  challenge?: string;
  code?: WebhookErrorCode;
  reason?: string;
}

/**
 * Verifies Meta's initial GET webhook setup challenge handshake.
 *
 * @param query Object or URL containing query parameters (hub.mode, hub.challenge, hub.verify_token).
 * @param expectedVerifyToken The secret verify token configured in Meta App Dashboard.
 */
export function verifyMetaChallenge(
  query: MetaChallengeQueryParams | string | URL,
  expectedVerifyToken: string,
): MetaChallengeResult {
  let mode: string | undefined;
  let challenge: string | undefined;
  let verifyToken: string | undefined;

  if (typeof query === "string" || query instanceof URL) {
    const urlObj =
      typeof query === "string" ? new URL(query, "http://localhost") : query;
    mode = urlObj.searchParams.get("hub.mode") || undefined;
    challenge = urlObj.searchParams.get("hub.challenge") || undefined;
    verifyToken = urlObj.searchParams.get("hub.verify_token") || undefined;
  } else {
    mode = query["hub.mode"];
    challenge = query["hub.challenge"];
    verifyToken = query["hub.verify_token"];
  }

  if (
    mode === "subscribe" &&
    verifyToken === expectedVerifyToken &&
    challenge
  ) {
    return {
      valid: true,
      challenge,
    };
  }

  return {
    valid: false,
    code: WebhookErrorCode.INVALID_SIGNATURE,
    reason:
      mode !== "subscribe"
        ? `Invalid hub.mode "${mode}". Expected "subscribe".`
        : "Verify token mismatch or missing hub.challenge",
  };
}
