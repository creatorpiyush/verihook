/** `verihook/calendly`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { calendlyVerifier } from "../providers/calendly.js";

export const verifyCalendly: ProviderVerifyFunction<"calendly"> = bindVerifier(
  "calendly",
  calendlyVerifier,
);

export { calendlyVerifier };
export type { CalendlyEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
