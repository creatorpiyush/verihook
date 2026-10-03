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
  parsePayload,
  payloadTooLargeReply,
  securityHeaders,
  toVerihookContext,
  type AdapterReply,
  type SecretResolver,
  type VerihookContext,
} from "./shared.js";
import { normalizeBody } from "../utils/normalize-request.js";

/** The parts of a `FastifyRequest` the hook uses. */
export interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: string | Uint8Array;
  url: string;
  method: string;
  protocol?: string;
}

/** The parts of a `FastifyReply` the hook uses. */
export interface FastifyReplyLike {
  code(statusCode: number): this;
  headers(values: Record<string, string>): this;
  send(payload?: unknown): this;
  statusCode: number;
  raw: { on(event: "finish", listener: () => void): unknown };
}

/** Fields the hook adds to the request. */
export interface VerihookFastifyRequest<TEvent = unknown> {
  rawBody?: string | Uint8Array;
  verihook?: VerihookContext<TEvent>;
}

export interface VerihookFastifyOptions extends VerifyWebhookOptions {
  /**
   * Custom handler invoked when verification fails or throws, instead of the
   * default 401/200/500 reply. Send a reply from it to stop the route.
   */
  onError?: (
    result: VerificationResult,
    request: FastifyRequestLike,
    reply: FastifyReplyLike,
  ) => unknown;
}

function send(reply: FastifyReplyLike, { status, body }: AdapterReply) {
  return reply.code(status).headers(securityHeaders).send(body);
}

interface FastifyInstanceLike {
  hasContentTypeParser(contentType: string): boolean;
  removeContentTypeParser(contentType: string | string[]): unknown;
  addContentTypeParser(
    contentType: string | string[],
    opts: { parseAs: "buffer" },
    parser: (
      request: VerihookFastifyRequest,
      body: Buffer,
      done: (err: Error | null, body?: unknown) => void,
    ) => void,
  ): unknown;
}

function badRequest(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 400 });
}

/**
 * Fastify plugin that keeps the raw body (`request.rawBody`) the signature was computed
 * over, while still parsing JSON and form bodies into `request.body`. Register it in the
 * scope of your webhook routes: `app.register(verihookRawBody)`.
 */
export function verihookRawBody(
  // `any` so it's assignable to Fastify's own plugin type without importing it.
  instance: any,
  _opts: unknown,
  done: (err?: Error) => void,
): void {
  const fastify = instance as FastifyInstanceLike;
  const replace = (type: string, parse: (text: string) => unknown): void => {
    if (fastify.hasContentTypeParser(type)) {
      fastify.removeContentTypeParser(type);
    }
    fastify.addContentTypeParser(
      type,
      { parseAs: "buffer" },
      (request, body, parsed) => {
        request.rawBody = body;
        try {
          parsed(null, parse(body.toString("utf-8")));
        } catch {
          parsed(badRequest("Body is not valid for its content type"));
        }
      },
    );
  };

  replace("application/json", (text) =>
    text === "" ? undefined : JSON.parse(text),
  );
  replace("application/x-www-form-urlencoded", (text) =>
    Object.fromEntries(new URLSearchParams(text)),
  );
  replace("*", (text) => text);
  done();
}
// Like `fastify-plugin`: apply to the registering scope instead of a child context.
(verihookRawBody as unknown as Record<symbol, boolean>)[
  Symbol.for("skip-override")
] = true;

/**
 * Fastify `preHandler` hook that verifies the webhook, then sets `request.verihook`.
 * Needs the raw body: register `verihookRawBody` (or a parser with `parseAs: "buffer"`).
 *
 * ```ts
 * app.register(verihookRawBody);
 * app.post("/webhooks/stripe", { preHandler: verihookFastify("stripe", secret) }, async (request) => {
 *   const { event } = (request as VerihookFastifyRequest<StripeEvent>).verihook!;
 * });
 * ```
 */
export function verihookFastify<
  TEvent = never,
  P extends ProviderName = ProviderName,
>(
  provider: P,
  secret: SecretResolver<FastifyRequestLike>,
  options?: VerihookFastifyOptions,
): (request: any, reply: any) => Promise<unknown> {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;

  return async (
    request: FastifyRequestLike & VerihookFastifyRequest,
    reply: FastifyReplyLike,
  ): Promise<unknown> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(request) : secret;

      // A string/Buffer body (from a `parseAs` parser) is the raw body too.
      const body = request.body;
      const rawBody =
        request.rawBody ??
        (typeof body === "string" || body instanceof Uint8Array
          ? body
          : undefined);
      const size =
        rawBody === undefined
          ? 0
          : typeof rawBody === "string"
            ? Buffer.byteLength(rawBody)
            : rawBody.byteLength;
      if (size > maxBytes) {
        return send(reply, payloadTooLargeReply(maxBytes));
      }

      const result: VerificationResult<ResolveEvent<TEvent, P>> =
        await verifyWebhook<TEvent, P>(
          provider,
          {
            headers: request.headers,
            body: request.body,
            rawBody,
            url: request.url,
            method: request.method,
            protocol: request.protocol,
          },
          resolvedSecret,
          options,
        );

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, request, reply);
        }
        return send(reply, failureReply(result));
      }

      const payload =
        rawBody === undefined ? body : parsePayload(normalizeBody(rawBody));
      request.verihook = toVerihookContext(provider, payload, result);

      // If the route fails, forget the event so the provider's retry is handled.
      if (result.dedupeKey) {
        reply.raw.on("finish", () => {
          if (reply.statusCode >= 500) {
            void releaseDedupeKey(result, options);
          }
        });
      }
    } catch (err: unknown) {
      if (options?.onError) {
        return await options.onError(
          exceptionResult(provider, err),
          request,
          reply,
        );
      }
      return send(reply, INTERNAL_ERROR_REPLY);
    }
    return undefined;
  };
}
