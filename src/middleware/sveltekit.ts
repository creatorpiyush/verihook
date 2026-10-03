import type { ProviderName, VerificationResult } from "../core/types.js";
import type { ResolveEvent } from "../core/event-types.js";
import {
  createWebAdapter,
  type SecretResolver,
  type WebAdapterOptions,
} from "./shared.js";

/** The parts of SvelteKit's `RequestEvent` the handler uses. */
export interface SvelteKitEventLike {
  request: Request;
}

export type VerihookSvelteKitOptions<
  Event extends SvelteKitEventLike = SvelteKitEventLike,
> = WebAdapterOptions<Event>;

/** `result.event` is the parsed payload, typed for built-in providers. */
export type SvelteKitWebhookCallback<
  TEvent = unknown,
  Event extends SvelteKitEventLike = SvelteKitEventLike,
> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  event: Event,
) => Promise<Response | void> | Response | void;

/**
 * SvelteKit `+server.ts` request handler that verifies the webhook before calling `handler`.
 *
 * ```ts
 * export const POST = createWebhookHandler("stripe", env.STRIPE_WEBHOOK_SECRET, async (payload, result) => {
 *   // result.event is a typed Stripe event
 * });
 * ```
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
  Event extends SvelteKitEventLike = SvelteKitEventLike,
>(
  provider: P,
  secret: SecretResolver<Event>,
  handler: SvelteKitWebhookCallback<ResolveEvent<TEvent, P>, Event>,
  options?: VerihookSvelteKitOptions<Event>,
): (event: Event) => Promise<Response> {
  return createWebAdapter(
    provider,
    secret,
    handler,
    options,
    (event) => event.request,
  );
}
