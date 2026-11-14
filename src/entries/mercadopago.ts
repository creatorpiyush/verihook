/** `verihook/mercadopago`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { mercadopagoVerifier } from "../providers/mercadopago.js";

export const verifyMercadoPago: ProviderVerifyFunction<"mercadopago"> =
  bindVerifier("mercadopago", mercadopagoVerifier);

export { mercadopagoVerifier };
export type { MercadoPagoEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
