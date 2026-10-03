import { releaseDedupeKey } from "../core/dedupe.js";
import {
  WebhookErrorCode,
  type ProviderName,
  type VerificationResult,
  type VerifyWebhookOptions,
} from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";

/** A webhook secret, or a function that resolves it from the framework's request/context. */
export type SecretResolver<Req> =
  string | ((req: Req) => string | Promise<string>);

export const DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024; // 2MB

export const securityHeaders: Record<string, string> = {
  "Content-Type": "application/json",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

/** Fields the adapters expose to downstream handlers (`req.verihook`, `c.get("verihook")`, ...). */
export interface VerihookContext<TEvent = unknown> {
  valid: true;
  provider: ProviderName;
  /** Parsed JSON body, or the raw string when it isn't JSON. */
  payload: unknown;
  /** Parsed payload (JSON, or form fields), same as `result.event`. */
  event?: TEvent;
  /** Event name, e.g. `"invoice.paid"`, same as `result.eventType`. */
  eventType?: string;
  timestamp?: number;
  result: VerificationResult<TEvent>;
}

/** The HTTP reply an adapter sends when it handles the request itself. */
export interface AdapterReply {
  status: number;
  body: Record<string, unknown>;
}

export const DUPLICATE_REPLY: AdapterReply = {
  status: 200,
  body: { received: true, duplicate: true },
};

export const INTERNAL_ERROR_REPLY: AdapterReply = {
  // Details stay server-side (onError / telemetry); clients get a generic message.
  status: 500,
  body: { error: "Internal webhook verification error" },
};

export function payloadTooLargeReply(maxBytes: number): AdapterReply {
  return {
    status: 413,
    body: {
      error: `Payload size exceeds limit of ${maxBytes} bytes`,
      code: "PAYLOAD_TOO_LARGE",
    },
  };
}

/**
 * The default reply for a failed verification. Duplicates are acknowledged with 2xx
 * so the provider stops retrying them.
 */
export function failureReply(result: VerificationResult): AdapterReply {
  if (result.code === WebhookErrorCode.DUPLICATE_EVENT) {
    return DUPLICATE_REPLY;
  }
  return { status: 401, body: { error: result.reason, code: result.code } };
}

export function jsonResponse(reply: AdapterReply): Response {
  return new Response(JSON.stringify(reply.body), {
    status: reply.status,
    headers: securityHeaders,
  });
}

/** Wraps an exception thrown during verification in a failed result for `onError`. */
export function exceptionResult(
  provider: ProviderName,
  err: unknown,
): VerificationResult {
  return {
    valid: false,
    provider,
    reason: err instanceof Error ? err.message : "Verification exception",
    error: err instanceof Error ? err : new Error(String(err)),
  };
}

export function parsePayload(rawBody: string): unknown {
  try {
    return JSON.parse(rawBody);
  } catch {
    return rawBody;
  }
}

export function toVerihookContext<TEvent>(
  provider: ProviderName,
  payload: unknown,
  result: VerificationResult<TEvent>,
): VerihookContext<TEvent> {
  return {
    valid: true,
    provider,
    payload,
    event: result.event,
    eventType: result.eventType,
    timestamp: result.timestamp,
    result,
  };
}

export class PayloadTooLargeError extends Error {}

/**
 * Reads a Web `Request` body as UTF-8, aborting once it exceeds `maxBytes`.
 */
export async function readWebBodyWithLimit(
  req: Request,
  maxBytes: number,
): Promise<string> {
  const declaredLength = Number(req.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new PayloadTooLargeError();
  }
  if (!req.body) {
    return "";
  }

  const reader = req.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      // Not awaited: cancelling one branch of a cloned (tee'd) body only settles
      // once the other branch is consumed or cancelled, which may never happen.
      reader.cancel().catch(() => {});
      throw new PayloadTooLargeError();
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/**
 * Reads a Node.js readable stream (e.g. `IncomingMessage`) into a Buffer,
 * aborting once it exceeds `maxBytes`.
 */
export async function readNodeBodyWithLimit(
  stream: AsyncIterable<Uint8Array | string>,
  maxBytes: number,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of stream) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    totalBytes += buf.length;
    if (totalBytes > maxBytes) {
      throw new PayloadTooLargeError();
    }
    chunks.push(Buffer.from(buf));
  }
  return Buffer.concat(chunks);
}

export interface WebAdapterOptions<Ctx> extends VerifyWebhookOptions {
  /**
   * Custom handler invoked when verification fails or throws. Its Response is
   * returned instead of the default 401/200/500 reply.
   */
  onError?: (
    result: VerificationResult,
    ctx: Ctx,
  ) => Response | Promise<Response>;
}

export type WebWebhookCallback<TEvent, Ctx> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  ctx: Ctx,
) => Promise<Response | void> | Response | void;

/**
 * Builds a Web-standard `(ctx) => Promise<Response>` handler shared by the
 * Next.js, SvelteKit, Remix, Astro and h3 adapters. `getRequest` pulls the
 * Fetch `Request` out of the framework's handler argument.
 */
export function createWebAdapter<TEvent, Ctx>(
  provider: ProviderName,
  secret: SecretResolver<Ctx>,
  handler: WebWebhookCallback<TEvent, Ctx>,
  options: WebAdapterOptions<Ctx> | undefined,
  getRequest: (ctx: Ctx) => Request | Promise<Request>,
): (ctx: Ctx) => Promise<Response> {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;

  return async (ctx: Ctx): Promise<Response> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(ctx) : secret;
      let req: Request;
      let rawBody: string;
      try {
        req = await getRequest(ctx);
        rawBody = await readWebBodyWithLimit(req.clone(), maxBytes);
      } catch (err) {
        if (!(err instanceof PayloadTooLargeError)) throw err;
        return jsonResponse(payloadTooLargeReply(maxBytes));
      }

      const result = (await verifyWebhook(
        provider,
        { headers: req.headers, rawBody, url: req.url, method: req.method },
        resolvedSecret,
        options,
      )) as VerificationResult<TEvent>;

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, ctx);
        }
        return jsonResponse(failureReply(result));
      }

      let handlerResult: Response | void;
      try {
        handlerResult = await handler(parsePayload(rawBody), result, ctx);
      } catch (handlerErr) {
        // Forget the event so the provider's retry is processed, not rejected as a duplicate.
        await releaseDedupeKey(result, options);
        throw handlerErr;
      }

      if (handlerResult instanceof Response) {
        if (handlerResult.status >= 500) {
          await releaseDedupeKey(result, options);
        }
        return handlerResult;
      }

      return jsonResponse({ status: 200, body: { received: true } });
    } catch (err: unknown) {
      if (options?.onError) {
        return await options.onError(exceptionResult(provider, err), ctx);
      }
      return jsonResponse(INTERNAL_ERROR_REPLY);
    }
  };
}
