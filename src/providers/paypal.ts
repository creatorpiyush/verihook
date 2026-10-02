import { computeCrc32, verifyRsaSha256 } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";

// Exact hosts PayPal serves webhook signing certificates from.
const PAYPAL_CERT_HOSTS = new Set([
  "api.paypal.com",
  "api-m.paypal.com",
  "api.sandbox.paypal.com",
  "api-m.sandbox.paypal.com",
]);

const CERT_FETCH_TIMEOUT_MS = 5_000;
const CERT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CERT_CACHE_MAX_SIZE = 50;

// Certificate URLs are content-addressed (CERT-<id>), so caching by URL is safe.
const certCache = new Map<string, { pem: string; expiresAt: number }>();

function isPem(value: string | undefined): value is string {
  return !!value && value.includes("-----BEGIN");
}

function isTrustedCertUrl(certUrl: string): boolean {
  try {
    const parsed = new URL(certUrl);
    return (
      parsed.protocol === "https:" &&
      parsed.port === "" &&
      PAYPAL_CERT_HOSTS.has(parsed.hostname.toLowerCase())
    );
  } catch {
    return false;
  }
}

async function fetchCert(certUrl: string): Promise<string | undefined> {
  const now = Date.now();
  const cached = certCache.get(certUrl);
  if (cached && cached.expiresAt > now) {
    return cached.pem;
  }
  certCache.delete(certUrl);

  if (typeof fetch !== "function") {
    return undefined;
  }

  const signal =
    typeof AbortSignal !== "undefined" &&
    typeof AbortSignal.timeout === "function"
      ? AbortSignal.timeout(CERT_FETCH_TIMEOUT_MS)
      : undefined;

  const res = await fetch(certUrl, { signal, redirect: "error" });
  if (!res.ok) {
    return undefined;
  }
  const pem = await res.text();
  if (!isPem(pem)) {
    return undefined;
  }

  if (certCache.size >= CERT_CACHE_MAX_SIZE) {
    const oldestKey = certCache.keys().next().value;
    if (oldestKey !== undefined) certCache.delete(oldestKey);
  }
  certCache.set(certUrl, { pem, expiresAt: now + CERT_CACHE_TTL_MS });
  return pem;
}

/**
 * Clears the in-process PayPal signing certificate cache (useful for tests).
 */
export function clearPayPalCertCache(): void {
  certCache.clear();
}

export const paypalVerifier: ProviderVerifier = {
  name: "paypal",
  requiresSecret: false, // Auth via RSA cert chain / webhookId, not a shared HMAC secret
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const transmissionId = req.headers["paypal-transmission-id"];
    const transmissionTime = req.headers["paypal-transmission-time"];
    const transmissionSig = req.headers["paypal-transmission-sig"];
    const certUrl = req.headers["paypal-cert-url"];

    if (!transmissionId || !transmissionTime || !transmissionSig) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing PayPal headers ("paypal-transmission-id", "paypal-transmission-time", or "paypal-transmission-sig")',
      };
    }

    // `secret` is either a pinned PEM public key/cert, or the webhook ID itself.
    const webhookId = options?.webhookId || (isPem(secret) ? "" : secret);
    if (!webhookId) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.INVALID_SECRET,
        reason:
          "PayPal webhook ID is required. Pass options.webhookId (or the webhook ID as secret)",
      };
    }

    let publicKeyOrCert: string | undefined;
    if (isPem(secret)) {
      publicKeyOrCert = secret;
    } else if (!certUrl) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "paypal-cert-url" header. PayPal signatures can only be verified against a PayPal signing certificate',
      };
    } else if (!isTrustedCertUrl(certUrl)) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: `Untrusted "paypal-cert-url" host: ${certUrl}`,
      };
    } else {
      try {
        publicKeyOrCert = await fetchCert(certUrl);
      } catch {
        publicKeyOrCert = undefined;
      }
      if (!publicKeyOrCert) {
        return {
          valid: false,
          provider: "paypal",
          code: WebhookErrorCode.INVALID_SIGNATURE,
          reason: "Unable to fetch PayPal signing certificate",
        };
      }
    }

    const bodyCrc = computeCrc32(req.rawBody);
    const expectedPayload = `${transmissionId}|${transmissionTime}|${webhookId}|${bodyCrc}`;

    const isValid = await verifyRsaSha256(
      publicKeyOrCert,
      transmissionSig,
      expectedPayload,
    );
    if (!isValid) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "PayPal RSA-SHA256 signature verification failed",
      };
    }

    return { valid: true, provider: "paypal" };
  },
};
