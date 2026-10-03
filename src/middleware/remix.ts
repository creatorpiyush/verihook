import type { ProviderName, VerificationResult } from "../core/types.js";
import type { ResolveEvent } from "../core/event-types.js";
import {
  createWebAdapter,
  type SecretResolver,
  type WebAdapterOptions,
} from "./shared.js";

/** The parts of Remix / React Router `ActionFunctionArgs` the handler uses. */
export interface RemixActionArgsLike {
  request: Request;
}

export type VerihookRemixOptions<
  Args extends RemixActionArgsLike = RemixActionArgsLike,
> = WebAdapterOptions<Args>;

/** `result.event` is the parsed payload, typed for built-in providers. */
export type RemixWebhookCallback<
  TEvent = unknown,
  Args extends RemixActionArgsLike = RemixActionArgsLike,
> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  args: Args,
) => Promise<Response | void> | Response | void;

/**
 * Remix / React Router route `action` that verifies the webhook before calling `handler`.
 *
 * ```ts
 * export const action = createWebhookHandler("github", process.env.GITHUB_WEBHOOK_SECRET!, async (payload, result) => {
 *   // result.event is a typed GitHub event
 * });
 * ```
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
  Args extends RemixActionArgsLike = RemixActionArgsLike,
>(
  provider: P,
  secret: SecretResolver<Args>,
  handler: RemixWebhookCallback<ResolveEvent<TEvent, P>, Args>,
  options?: VerihookRemixOptions<Args>,
): (args: Args) => Promise<Response> {
  return createWebAdapter(
    provider,
    secret,
    handler,
    options,
    (args) => args.request,
  );
}
