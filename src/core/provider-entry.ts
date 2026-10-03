import type { EventFor } from "./event-types.js";
import { runVerification } from "./run.js";
import {
  ProviderName,
  ProviderVerifier,
  ProviderVerifyFunction,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "./types.js";

/**
 * Binds one verifier to the shared pipeline for the per-provider entry points
 * (`verihook/stripe`, ...). It skips the provider registry, so `registerProvider`
 * overrides apply to `verifyWebhook` only.
 */
export function bindVerifier<P extends ProviderName>(
  provider: P,
  verifier: ProviderVerifier,
): ProviderVerifyFunction<P> {
  return <TEvent = EventFor<P>>(
    req: WebhookRequestInput,
    secret: string,
    opts?: VerifyWebhookOptions,
  ) =>
    runVerification(provider, () => verifier, req, secret, opts) as Promise<
      VerificationResult<TEvent>
    >;
}
