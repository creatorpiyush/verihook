import { releaseDedupeKey } from "../core/dedupe.js";
import type {
  ProviderName,
  VerificationResult,
  VerifyWebhookOptions,
} from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";
import { normalizeBody } from "../utils/normalize-request.js";
import {
  DEFAULT_MAX_BODY_SIZE,
  exceptionResult,
  failureReply,
  INTERNAL_ERROR_REPLY,
  parsePayload,
  payloadTooLargeReply,
  securityHeaders,
  toVerihookContext,
  type AdapterReply,
  type SecretResolver,
  type VerihookContext,
} from "./shared.js";

/** The parts of an Express or Fastify request (as Nest passes it) the guard uses. */
export interface NestRequestLike {
  headers: Record<string, string | string[] | undefined>;
  /** Set by Nest when the app is created with `{ rawBody: true }`. */
  rawBody?: string | Uint8Array;
  body?: unknown;
  url?: string;
  originalUrl?: string;
  method?: string;
  protocol?: string;
  verihook?: VerihookContext;
}

/** The parts of Nest's `ExecutionContext` the guard uses. */
export interface NestExecutionContextLike {
  switchToHttp(): {
    getRequest<T = any>(): T;
    getResponse<T = any>(): T;
  };
}

/** Fields the guard adds to the request. */
export interface VerihookNestRequest<TEvent = unknown> {
  verihook?: VerihookContext<TEvent>;
}

export interface VerihookGuardOptions extends VerifyWebhookOptions {
  /**
   * Builds the exception thrown when verification fails or throws (including
   * duplicates), e.g. `(result) => new UnauthorizedException(result.reason)`, so
   * your exception filters shape the reply. By default the guard replies itself.
   */
  exceptionFactory?: (result: VerificationResult) => unknown;
}

export interface VerihookGuard {
  canActivate(context: NestExecutionContextLike): Promise<boolean>;
}

/** Replies through Express (`res.status().json()`) or Fastify (`reply.code().send()`). */
function sendReply(res: any, { status, body }: AdapterReply): void {
  if (typeof res.status === "function" && typeof res.json === "function") {
    for (const [name, value] of Object.entries(securityHeaders)) {
      res.setHeader?.(name, value);
    }
    res.status(status).json(body);
  } else if (typeof res.code === "function") {
    res.code(status).headers(securityHeaders).send(body);
  } else {
    throw new Error("[verihook] Unsupported Nest HTTP adapter response");
  }
}

/** Runs `listener` once the response is sent, on Express or Fastify. */
function onFinish(res: any, listener: (statusCode: number) => void): void {
  const raw = typeof res.on === "function" ? res : res.raw;
  raw?.on?.("finish", () => listener(raw.statusCode ?? res.statusCode ?? 200));
}

/**
 * NestJS guard that verifies the webhook, then sets `req.verihook` for the route
 * handler. Create the app with `NestFactory.create(AppModule, { rawBody: true })` so
 * Nest keeps the raw body. Works with the Express and Fastify platforms.
 *
 * ```ts
 * @Post("webhooks/stripe")
 * @UseGuards(createVerihookGuard("stripe", process.env.STRIPE_WEBHOOK_SECRET!))
 * handle(@Req() req: Request & VerihookNestRequest<StripeEvent>) {
 *   const { event } = req.verihook!;
 * }
 * ```
 *
 * On failure the guard replies itself (401, or 200 for duplicates) and returns
 * `false`; Nest sees the reply was sent and doesn't send a 403 on top. Pass
 * `exceptionFactory` to throw your own exception instead.
 */
export function createVerihookGuard(
  provider: ProviderName,
  secret: SecretResolver<NestRequestLike>,
  options?: VerihookGuardOptions,
): VerihookGuard {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;

  type Outcome =
    | { ok: true; result: VerificationResult }
    | { ok: false; result: VerificationResult; reply: AdapterReply };

  const verify = async (req: NestRequestLike): Promise<Outcome> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(req) : secret;

      const rawBody =
        req.rawBody ??
        (typeof req.body === "string" || req.body instanceof Uint8Array
          ? req.body
          : undefined);
      const size =
        rawBody === undefined
          ? 0
          : typeof rawBody === "string"
            ? Buffer.byteLength(rawBody)
            : rawBody.byteLength;
      if (size > maxBytes) {
        const reply = payloadTooLargeReply(maxBytes);
        const reason = String(reply.body.error);
        return { ok: false, result: { valid: false, provider, reason }, reply };
      }

      const result = await verifyWebhook(
        provider,
        {
          headers: req.headers,
          body: req.body,
          rawBody,
          url: req.originalUrl ?? req.url,
          method: req.method,
          protocol: req.protocol,
        },
        resolvedSecret,
        options,
      );
      if (!result.valid) {
        return { ok: false, result, reply: failureReply(result) };
      }

      const payload =
        rawBody === undefined ? req.body : parsePayload(normalizeBody(rawBody));
      req.verihook = toVerihookContext(provider, payload, result);
      return { ok: true, result };
    } catch (err: unknown) {
      return {
        ok: false,
        result: exceptionResult(provider, err),
        reply: INTERNAL_ERROR_REPLY,
      };
    }
  };

  return {
    async canActivate(context) {
      const http = context.switchToHttp();
      const req = http.getRequest<NestRequestLike>();
      const res = http.getResponse<unknown>();

      const outcome = await verify(req);
      if (!outcome.ok) {
        if (options?.exceptionFactory) {
          throw options.exceptionFactory(outcome.result);
        }
        sendReply(res, outcome.reply);
        return false;
      }
      const { result } = outcome;

      // If the route fails, forget the event so the provider's retry is handled.
      if (result.dedupeKey) {
        onFinish(res, (statusCode) => {
          if (statusCode >= 500) {
            void releaseDedupeKey(result, options);
          }
        });
      }
      return true;
    },
  };
}
