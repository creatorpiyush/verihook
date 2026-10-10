import {
  VerificationResult,
  WebhookErrorCode,
  type ProviderName,
} from "../core/types.js";

/** The result for a weaker fallback scheme rejected by `options.strict`. */
export function weakScheme(
  provider: ProviderName,
  reason: string,
): VerificationResult {
  return {
    valid: false,
    provider,
    code: WebhookErrorCode.WEAK_SCHEME,
    reason: `${reason} (rejected by options.strict)`,
  };
}
