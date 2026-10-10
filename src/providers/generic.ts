import { computeHmac, timingSafeEqual } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToBase64, bytesToHex } from "../utils/encoding.js";

const ALGORITHMS = new Map<string, "SHA-256" | "SHA-1" | "SHA-512">([
  ["sha256", "SHA-256"],
  ["sha1", "SHA-1"],
  ["sha512", "SHA-512"],
]);
const ENCODINGS = new Set(["hex", "base64", "prefix-hex"]);

export const genericVerifier: ProviderVerifier = {
  name: "generic",
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const algorithmName = options?.algorithm ?? "sha256";
    const encoding = options?.encoding ?? "hex";
    const alg = ALGORITHMS.get(algorithmName);
    // An unknown value would leave the expected signature empty.
    if (!alg) {
      throw new TypeError(`Unsupported generic algorithm: ${algorithmName}`);
    }
    if (!ENCODINGS.has(encoding)) {
      throw new TypeError(`Unsupported generic encoding: ${encoding}`);
    }

    const headerName = options?.headerName?.toLowerCase() || "x-signature";
    const signature = req.headers[headerName]?.trim();

    if (!signature) {
      return {
        valid: false,
        provider: "generic",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: `Missing signature header "${headerName}"`,
      };
    }

    const hmacBytes = await computeHmac(alg, secret, req.rawBody);
    let expectedSig = "";

    if (encoding === "hex") {
      expectedSig = bytesToHex(hmacBytes);
    } else if (encoding === "base64") {
      expectedSig = bytesToBase64(hmacBytes);
    } else if (encoding === "prefix-hex") {
      expectedSig = `${algorithmName}=${bytesToHex(hmacBytes)}`;
    }

    let cleanSignature = signature;
    if (encoding === "prefix-hex" && !cleanSignature.includes("=")) {
      cleanSignature = `${algorithmName}=${cleanSignature}`;
    }

    const isHexEncoding = encoding === "hex" || encoding === "prefix-hex";
    const finalCleanSig = isHexEncoding
      ? cleanSignature.toLowerCase()
      : cleanSignature;
    const finalExpectedSig = isHexEncoding
      ? expectedSig.toLowerCase()
      : expectedSig;

    if (!timingSafeEqual(finalCleanSig, finalExpectedSig)) {
      return {
        valid: false,
        provider: "generic",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "generic",
    };
  },
};
