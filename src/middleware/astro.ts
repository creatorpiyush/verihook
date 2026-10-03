import type { ProviderName, VerificationResult } from "../core/types.js";
import type { ResolveEvent } from "../core/event-types.js";
import {
  createWebAdapter,
  type SecretResolver,
  type WebAdapterOptions,
} from "./shared.js";

/** The parts of Astro's `APIContext` the handler uses. */
export interface AstroContextLike {
  request: Request;
}

export type VerihookAstroOptions<
  Ctx extends AstroContextLike = AstroContextLike,
> = WebAdapterOptions<Ctx>;

/** `result.event` is the parsed payload, typed for built-in providers. */
export type AstroWebhookCallback<
  TEvent = unknown,
  Ctx extends AstroContextLike = AstroContextLike,
> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  context: Ctx,
) => Promise<Response | void> | Response | void;

/**
 * Astro API route (`src/pages/api/*.ts`) that verifies the webhook before calling `handler`.
 * The route must be server-rendered (`export const prerender = false` in hybrid/static output).
 *
 * ```ts
 * export const POST = createWebhookHandler("shopify", import.meta.env.SHOPIFY_WEBHOOK_SECRET, async (payload, result) => {
 *   // result.event is a typed Shopify payload
 * });
 * ```
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
  Ctx extends AstroContextLike = AstroContextLike,
>(
  provider: P,
  secret: SecretResolver<Ctx>,
  handler: AstroWebhookCallback<ResolveEvent<TEvent, P>, Ctx>,
  options?: VerihookAstroOptions<Ctx>,
): (context: Ctx) => Promise<Response> {
  return createWebAdapter(
    provider,
    secret,
    handler,
    options,
    (context) => context.request,
  );
}
