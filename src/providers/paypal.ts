import {
  computeCrc32,
  computeHmacSha256,
  timingSafeEqual,
  verifyRsaSha256,
} from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";

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

    const webhookId = options?.webhookId || secret;
    const bodyCrc = computeCrc32(req.rawBody);
    const expectedPayload = `${transmissionId}|${transmissionTime}|${webhookId}|${bodyCrc}`;

    // If secret contains a PEM public key/cert or certUrl is provided, verify via RSA-SHA256
    let rsaPublicKeyOrCert: string | undefined;
    if (secret && secret.includes("-----BEGIN")) {
      rsaPublicKeyOrCert = secret;
    } else if (certUrl) {
      try {
        const parsedCertUrl = new URL(certUrl);
        const validHostnames = [
          "api.paypal.com",
          "api.sandbox.paypal.com",
          "api.msmaster.qa.paypal.com",
        ];
        if (
          parsedCertUrl.protocol === "https:" &&
          validHostnames.some(
            (host) =>
              parsedCertUrl.hostname === host ||
              parsedCertUrl.hostname.endsWith(".paypal.com"),
          )
        ) {
          if (typeof fetch === "function") {
            const res = await fetch(certUrl);
            if (res.ok) {
              rsaPublicKeyOrCert = await res.text();
            }
          }
        }
      } catch {
        // Invalid certUrl format
      }
    }

    if (rsaPublicKeyOrCert) {
      const isValid = await verifyRsaSha256(
        rsaPublicKeyOrCert,
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
    }

    // HMAC Fallback verification mode when secret key is provided
    const hmacBytes = await computeHmacSha256(secret, expectedPayload);
    const expectedHex = bytesToHex(hmacBytes);

    if (
      !timingSafeEqual(
        transmissionSig.trim().toLowerCase(),
        expectedHex.toLowerCase(),
      )
    ) {
      return {
        valid: false,
        provider: "paypal",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "paypal",
    };
  },
};
