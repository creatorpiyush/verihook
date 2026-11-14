/**
 * Mercado Pago webhooks.
 *
 * Headers: `x-signature: ts=<unix seconds>,v1=<hex>` and `x-request-id`.
 * The signed manifest is `id:<data.id>;request-id:<x-request-id>;ts:<ts>;`, where
 * `data.id` is the query-string parameter as received; a pair whose value is
 * missing is left out. HMAC-SHA256, hex-encoded, keyed with the webhook secret.
 *
 * The body is not signed: treat it as a notification and fetch the resource from
 * the Mercado Pago API with the query's `data.id`. QR Code notifications are not
 * signed at all. Reference: `WebhookSignatureValidator` in the official SDK
 * (`mercadopago` on npm).
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { warnHintOnce } from "../core/diagnostics.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";
import { weakScheme } from "../utils/strict.js";
import { toEpochSeconds } from "../utils/timestamp.js";

/** `ts` and the `v1`, `v2`, ... hashes of an `x-signature` header. */
export function parseMercadoPagoSignature(header: string): {
  ts?: string;
  hashes: Record<string, string>;
} {
  const hashes: Record<string, string> = {};
  let ts: string | undefined;
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (!key || !value) continue;
    if (key === "ts") ts = value;
    else if (/^v\d+$/.test(key)) hashes[key] = value;
  }
  return { ts, hashes };
}

/** The `data.id` query parameter of the delivery URL, or undefined when absent or blank. */
export function mercadoPagoDataId(url: string): string | undefined {
  try {
    const value = new URL(url, "http://localhost").searchParams.get("data.id");
    return value?.trim() || undefined;
  } catch {
    return undefined;
  }
}

/** The string Mercado Pago signs; pairs with a missing value are left out. */
export function mercadoPagoManifest(
  dataId: string | undefined,
  requestId: string | undefined,
  ts: string,
): string {
  let manifest = "";
  if (dataId) manifest += `id:${dataId};`;
  if (requestId) manifest += `request-id:${requestId};`;
  return `${manifest}ts:${ts};`;
}

export const mercadopagoVerifier: ProviderVerifier = {
  name: "mercadopago",

  // e.g. "payment.created", else the topic ("payment"). Both come from the
  // unsigned body.
  eventType: (event) =>
    readString(event, "action") ?? readString(event, "type"),

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const header = req.headers["x-signature"]?.trim();
    if (!header) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature" header',
      };
    }

    const { ts, hashes } = parseMercadoPagoSignature(header);
    if (!ts || !/^\d+$/.test(ts) || !hashes.v1) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Malformed "x-signature" header: expected "ts=<unix seconds>,v1=<hex>"',
      };
    }

    // `data.id` is signed from the query string, so without the URL there is no
    // way to know whether it was part of the signature.
    const url = options?.url || req.url;
    if (!url) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.MISSING_URL,
        reason:
          "Missing request URL: Mercado Pago signs the data.id query parameter. Pass the request URL or options.url",
      };
    }
    const dataId = mercadoPagoDataId(url);
    const requestId = req.headers["x-request-id"]?.trim() || undefined;

    if (options?.strict && (!dataId || !requestId)) {
      const missing = [
        dataId ? "" : "the data.id query parameter",
        requestId ? "" : "the x-request-id header",
      ]
        .filter(Boolean)
        .join(" and ");
      return weakScheme(
        "mercadopago",
        `Mercado Pago signature doesn't cover ${missing}`,
      );
    }

    const timestamp = toEpochSeconds(Number(ts));
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "mercadopago",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const expected = bytesToHex(
      await computeHmacSha256(
        secret,
        mercadoPagoManifest(dataId, requestId, ts),
      ),
    );
    if (!timingSafeEqual(hashes.v1.toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: `Signature mismatch (data.id: ${dataId ?? "none"}, x-request-id: ${requestId ?? "none"})`,
      };
    }

    warnHintOnce(
      "mercadopago",
      "Mercado Pago doesn't sign the body. Treat result.event as a notification and fetch the resource from the API with the query's data.id.",
    );
    return { valid: true, provider: "mercadopago", timestamp };
  },
};
