import { releaseDedupeKey } from "../core/dedupe.js";
import type { ResolveEvent } from "../core/event-types.js";
import type {
  ProviderName,
  VerificationResult,
  VerifyWebhookOptions,
} from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";
import {
  DEFAULT_MAX_BODY_SIZE,
  exceptionResult,
  failureReply,
  INTERNAL_ERROR_REPLY,
  jsonResponse,
  parsePayload,
  PayloadTooLargeError,
  payloadTooLargeReply,
  readWebBodyWithLimit,
  toVerihookContext,
  type SecretResolver,
  type VerihookContext,
} from "./shared.js";

/** The parts of Hono's `Context` the middleware uses. */
export interface HonoContextLike {
  req: { raw: Request };
  res: Response;
  set(key: "verihook", value: VerihookContext<any>): void;
}

export interface VerihookHonoOptions<
  C extends HonoContextLike = HonoContextLike,
> extends VerifyWebhookOptions {
  /**
   * Custom handler invoked when verification fails or throws. Its Response is
   * returned instead of the default 401/200/500 reply.
   */
  onError?: (result: VerificationResult, c: C) => Response | Promise<Response>;
}

/**
 * Context variables set by the middleware. Use them in your app's type for a typed
 * `c.get("verihook")`: `new Hono<{ Variables: VerihookVariables<StripeEvent> }>()`.
 */
export interface VerihookVariables<TEvent = unknown> {
  verihook: VerihookContext<TEvent>;
}

/**
 * Hono middleware that verifies the webhook, then sets `c.get("verihook")` for the
 * route handler. The request body stays readable (`c.req.json()` still works).
 *
 * ```ts
 * app.post("/webhooks/stripe", verihookHono("stripe", (c) => c.env.STRIPE_WEBHOOK_SECRET), (c) => {
 *   const { event } = c.get("verihook");
 *   return c.json({ received: true });
 * });
 * ```
 */
export function verihookHono<
  TEvent = never,
  P extends ProviderName = ProviderName,
  C extends HonoContextLike = any,
>(
  provider: P,
  secret: SecretResolver<C>,
  options?: VerihookHonoOptions<C>,
): (c: C, next: () => Promise<void>) => Promise<Response | void> {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;

  return async (c, next) => {
    let result: VerificationResult<ResolveEvent<TEvent, P>>;
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(c) : secret;
      const req = c.req.raw;

      let rawBody: string;
      try {
        rawBody = await readWebBodyWithLimit(req.clone(), maxBytes);
      } catch (err) {
        if (!(err instanceof PayloadTooLargeError)) throw err;
        return jsonResponse(payloadTooLargeReply(maxBytes));
      }

      result = await verifyWebhook<TEvent, P>(
        provider,
        { headers: req.headers, rawBody, url: req.url, method: req.method },
        resolvedSecret,
        options,
      );

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, c);
        }
        return jsonResponse(failureReply(result));
      }

      c.set(
        "verihook",
        toVerihookContext(provider, parsePayload(rawBody), result),
      );
    } catch (err: unknown) {
      if (options?.onError) {
        return await options.onError(exceptionResult(provider, err), c);
      }
      return jsonResponse(INTERNAL_ERROR_REPLY);
    }

    try {
      await next();
    } catch (err) {
      // Forget the event so the provider's retry is processed, not rejected as a duplicate.
      await releaseDedupeKey(result, options);
      throw err;
    }
    // Hono turns handler errors into a 500 response before `next()` resolves.
    if (c.res.status >= 500) {
      await releaseDedupeKey(result, options);
    }
    return undefined;
  };
}
