/**
 * Adyen (Europe) webhooks. The secret is the HMAC key from the Customer Area (hex).
 *
 * Standard payment webhooks carry the signature inside each notification item:
 *   notificationItems[].NotificationRequestItem.additionalData.hmacSignature
 * It is the base64 HMAC-SHA256 (hex-decoded key) of these fields joined with ":":
 *   pspReference:originalReference:merchantAccountCode:merchantReference:
 *   amount.value:amount.currency:eventCode:success
 * Every item in the batch must verify.
 *
 * Platform, management and other webhooks sign the raw body instead, sending:
 *   HmacSignature: <base64 HMAC-SHA256 of the raw body>
 * https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64, hexToBytes } from "../utils/encoding.js";

type Item = Record<string, unknown>;

function field(value: unknown): string {
  return value === undefined || value === null ? "" : String(value);
}

/** The signed string for a standard notification item, as Adyen's SDKs build it. */
export function adyenSigningString(item: Item): string {
  const amount = (item.amount ?? {}) as Item;
  return [
    item.pspReference,
    item.originalReference,
    item.merchantAccountCode,
    item.merchantReference,
    amount.value,
    amount.currency,
    item.eventCode,
    item.success,
  ]
    .map(field)
    .join(":");
}

function notificationItems(event: unknown): Item[] | undefined {
  const items = (event as Item | null)?.notificationItems;
  if (!Array.isArray(items)) return undefined;
  return items.map(
    (entry) => ((entry as Item | null)?.NotificationRequestItem ?? {}) as Item,
  );
}

export const adyenVerifier: ProviderVerifier = {
  name: "adyen",

  eventType: (event) =>
    readString(notificationItems(event)?.[0], "eventCode") ??
    readString(event, "type"),

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    _options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    let key: Uint8Array;
    try {
      key = hexToBytes(secret.trim());
    } catch {
      return {
        valid: false,
        provider: "adyen",
        code: WebhookErrorCode.INVALID_SECRET,
        reason: "Adyen HMAC key must be the hex string from the Customer Area",
      };
    }

    const headerSignature = req.headers["hmacsignature"];
    if (headerSignature) {
      const expected = bytesToBase64(await computeHmacSha256(key, req.rawBody));
      if (!timingSafeEqual(headerSignature.trim(), expected)) {
        return {
          valid: false,
          provider: "adyen",
          code: WebhookErrorCode.INVALID_SIGNATURE,
          reason: "Signature mismatch",
        };
      }
      return { valid: true, provider: "adyen" };
    }

    let items: Item[] | undefined;
    try {
      items = notificationItems(JSON.parse(req.rawBody));
    } catch {
      items = undefined;
    }
    if (!items || items.length === 0) {
      return {
        valid: false,
        provider: "adyen",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "hmacsignature" header and no notificationItems in the body',
      };
    }

    for (const item of items) {
      const signature = readString(item, "additionalData", "hmacSignature");
      if (!signature) {
        return {
          valid: false,
          provider: "adyen",
          code: WebhookErrorCode.MISSING_HEADER,
          reason:
            "Missing additionalData.hmacSignature in a notification item (enable HMAC signing for the webhook)",
        };
      }
      const expected = bytesToBase64(
        await computeHmacSha256(key, adyenSigningString(item)),
      );
      if (!timingSafeEqual(signature.trim(), expected)) {
        return {
          valid: false,
          provider: "adyen",
          code: WebhookErrorCode.INVALID_SIGNATURE,
          reason: "Signature mismatch",
        };
      }
    }

    return { valid: true, provider: "adyen" };
  },
};
