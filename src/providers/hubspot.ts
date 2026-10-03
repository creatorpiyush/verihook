/**
 * HubSpot webhooks and app requests (CRM cards, workflow actions).
 *
 * v3 (current): headers `X-HubSpot-Signature-v3` and `X-HubSpot-Request-Timestamp`
 *   (Unix ms). Base64 HMAC-SHA256, keyed with the app's client secret, of
 *   `<method><uri><body><timestamp>`, where the URI has these escapes decoded:
 *   %3A %2F %3F %40 %21 %24 %27 %28 %29 %2A %2C %3B. Requests older than 5 minutes
 *   are rejected.
 * v1 / v2 (`X-HubSpot-Signature`, version in `X-HubSpot-Signature-Version`): hex
 *   SHA-256 of `<client secret><body>` (v1) or `<client secret><method><uri><body>` (v2).
 *
 * v2 and v3 sign the public URL HubSpot called, rebuilt like Twilio's (pass
 * `options.url` behind proxies that rewrite it).
 * https://developers.hubspot.com/docs/apps/legacy-apps/authentication/validating-requests
 */
import {
  computeHmacSha256,
  computeSha256,
  timingSafeEqual,
} from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64, bytesToHex } from "../utils/encoding.js";
import { resolveSignedUrl } from "../utils/request-url.js";
import { toEpochSeconds } from "../utils/timestamp.js";

const V3_DECODED: Record<string, string> = {
  "%3A": ":",
  "%2F": "/",
  "%3F": "?",
  "%40": "@",
  "%21": "!",
  "%24": "$",
  "%27": "'",
  "%28": "(",
  "%29": ")",
  "%2A": "*",
  "%2C": ",",
  "%3B": ";",
};

/** Decodes the URI escapes HubSpot's v3 signature leaves decoded. */
export function hubspotV3Uri(url: string): string {
  return url.replace(
    /%(3A|2F|3F|40|21|24|27|28|29|2A|2C|3B)/gi,
    (match) => V3_DECODED[match.toUpperCase()],
  );
}

function missingUrl(): VerificationResult {
  return {
    valid: false,
    provider: "hubspot",
    code: WebhookErrorCode.MISSING_URL,
    reason:
      "Missing request URL. Provide request URL or pass options.url explicitly for HubSpot v2/v3 verification",
  };
}

function mismatch(
  url: string | undefined,
  timestamp?: number,
): VerificationResult {
  return {
    valid: false,
    provider: "hubspot",
    code: WebhookErrorCode.INVALID_SIGNATURE,
    timestamp,
    reason: url
      ? `Signature mismatch (signed URL: ${url})`
      : "Signature mismatch",
  };
}

export const hubspotVerifier: ProviderVerifier = {
  name: "hubspot",
  // Webhook bodies are batches; this is the first event's `subscriptionType`.
  eventType: (event) =>
    Array.isArray(event)
      ? readString(event[0], "subscriptionType")
      : readString(event, "subscriptionType"),
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const method = (req.method || "POST").toUpperCase();
    const v3 = req.headers["x-hubspot-signature-v3"];

    if (v3) {
      const timestampStr = req.headers["x-hubspot-request-timestamp"];
      const rawTimestamp = Number(timestampStr);
      if (!timestampStr || !Number.isInteger(rawTimestamp)) {
        return {
          valid: false,
          provider: "hubspot",
          code: WebhookErrorCode.MISSING_HEADER,
          reason: 'Missing or invalid "x-hubspot-request-timestamp" header',
        };
      }

      const timestamp = toEpochSeconds(rawTimestamp);
      const tolerance = options?.tolerance ?? 300;
      if (tolerance > 0) {
        const now = toEpochSeconds(
          options?.now ?? Math.floor(Date.now() / 1000),
        );
        if (Math.abs(now - timestamp) > tolerance) {
          return {
            valid: false,
            provider: "hubspot",
            code: WebhookErrorCode.EXPIRED_TIMESTAMP,
            timestamp,
            reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
          };
        }
      }

      const url = resolveSignedUrl(req, options?.url);
      if (!url) return missingUrl();

      const expected = bytesToBase64(
        await computeHmacSha256(
          secret,
          `${method}${hubspotV3Uri(url)}${req.rawBody}${timestampStr}`,
        ),
      );
      if (!timingSafeEqual(v3.trim(), expected))
        return mismatch(url, timestamp);
      return { valid: true, provider: "hubspot", timestamp };
    }

    const signature = req.headers["x-hubspot-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "hubspot",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "x-hubspot-signature-v3" or "x-hubspot-signature" header',
      };
    }

    const version = (
      req.headers["x-hubspot-signature-version"] || "v1"
    ).toLowerCase();
    let source: string;
    let url: string | undefined;
    if (version === "v2") {
      url = resolveSignedUrl(req, options?.url);
      if (!url) return missingUrl();
      source = `${secret}${method}${url}${req.rawBody}`;
    } else if (version === "v1") {
      source = `${secret}${req.rawBody}`;
    } else {
      return {
        valid: false,
        provider: "hubspot",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: `Unsupported "x-hubspot-signature-version": ${version}`,
      };
    }

    const expected = bytesToHex(await computeSha256(source));
    if (!timingSafeEqual(signature.trim().toLowerCase(), expected)) {
      return mismatch(url);
    }
    return { valid: true, provider: "hubspot" };
  },
};
