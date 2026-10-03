import type { ProviderName, VerificationResult } from "../core/types.js";
import type { ResolveEvent } from "../core/event-types.js";
import {
  createWebAdapter,
  type SecretResolver,
  type WebAdapterOptions,
} from "./shared.js";

export interface VerihookNextOptions extends WebAdapterOptions<Request> {
  /**
   * Custom error handler function invoked when signature verification fails.
   */
  onError?: (
    result: VerificationResult,
    req: Request,
  ) => Response | Promise<Response>;
}

/** `result.event` is the parsed payload, typed for built-in providers. */
export type NextWebhookCallback<TEvent = unknown> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  req: Request,
) => Promise<Response | void> | Response | void;

/**
 * Next.js App Router & Web API Route Handler Factory for 1-line webhook verification.
 * Automatically verifies signatures, parses request payloads, executes callback logic,
 * and returns standardized HTTP responses with security headers.
 * Pass a type argument to type `result.event` yourself: `createWebhookHandler<MyEvent>(...)`.
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
>(
  provider: P,
  secret: SecretResolver<Request>,
  handler: NextWebhookCallback<ResolveEvent<TEvent, P>>,
  options?: VerihookNextOptions,
) {
  const handle = createWebAdapter(
    provider,
    secret,
    handler,
    options,
    (req: Request) => req,
  );
  return (req: Request, ..._extraArgs: unknown[]): Promise<Response> =>
    handle(req);
}
