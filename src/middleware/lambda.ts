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
  type AdapterReply,
  type SecretResolver,
} from "./shared.js";

/**
 * An API Gateway REST (v1) or HTTP API (v2) proxy event, or a Lambda Function URL
 * event (same shape as v2). Only the fields the handler uses are listed.
 */
export interface LambdaHttpEvent {
  headers?: Record<string, string | undefined> | null;
  body?: string | null;
  isBase64Encoded?: boolean;
  /** v1 */
  httpMethod?: string;
  path?: string;
  queryStringParameters?: Record<string, string | undefined> | null;
  /** v2 / Function URLs */
  rawPath?: string;
  rawQueryString?: string;
  requestContext?: {
    domainName?: string;
    /** v1: the path as requested, including the stage (`/prod/webhooks`). */
    path?: string;
    http?: { method?: string };
  };
}

export interface LambdaHttpResult {
  statusCode: number;
  headers?: Record<string, string | number | boolean>;
  body?: string;
  isBase64Encoded?: boolean;
}

export interface VerihookLambdaOptions<
  Event extends LambdaHttpEvent = LambdaHttpEvent,
> extends VerifyWebhookOptions {
  /**
   * Custom handler invoked when verification fails or throws. Its result is
   * returned instead of the default 401/200/500 reply.
   */
  onError?: (
    result: VerificationResult,
    event: Event,
  ) => LambdaHttpResult | Promise<LambdaHttpResult>;
}

/** `result.event` is the parsed payload, typed for built-in providers. */
export type LambdaWebhookCallback<
  TEvent = unknown,
  Event extends LambdaHttpEvent = LambdaHttpEvent,
  Context = unknown,
> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  event: Event,
  context: Context,
) => Promise<LambdaHttpResult | void> | LambdaHttpResult | void;

function toResult({ status, body }: AdapterReply): LambdaHttpResult {
  return {
    statusCode: status,
    headers: securityHeaders,
    body: JSON.stringify(body),
  };
}

/**
 * The public URL the request was sent to, for providers that sign it (Twilio, Square).
 * Behind a custom domain with a base path mapping, pass `options.url` instead.
 */
function eventUrl(
  event: LambdaHttpEvent,
  headers: Record<string, string>,
): string | undefined {
  const host = headers["x-forwarded-host"] || headers.host;
  const domain = host || event.requestContext?.domainName;
  if (!domain) return undefined;
  const proto = headers["x-forwarded-proto"]?.split(",")[0]?.trim() || "https";

  let path: string;
  let query: string;
  if (event.rawPath !== undefined) {
    path = event.rawPath;
    query = event.rawQueryString ?? "";
  } else {
    path = event.requestContext?.path ?? event.path ?? "/";
    query = new URLSearchParams(
      Object.entries(event.queryStringParameters ?? {}).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
      ),
    ).toString();
  }
  return `${proto}://${domain}${path}${query ? `?${query}` : ""}`;
}

/**
 * AWS Lambda handler for API Gateway (REST v1 and HTTP API v2) and Function URLs.
 * Decodes base64 bodies, verifies the webhook, then calls `handler`.
 *
 * ```ts
 * export const handler = createWebhookHandler("stripe", process.env.STRIPE_WEBHOOK_SECRET!, async (payload, result) => {
 *   // result.event is a typed Stripe event
 * });
 * ```
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
  Event extends LambdaHttpEvent = LambdaHttpEvent,
  Context = unknown,
>(
  provider: P,
  secret: SecretResolver<Event>,
  handler: LambdaWebhookCallback<ResolveEvent<TEvent, P>, Event, Context>,
  options?: VerihookLambdaOptions<Event>,
): (event: Event, context: Context) => Promise<LambdaHttpResult> {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;

  return async (event, context) => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(event) : secret;

      const bytes = event.body
        ? Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf-8")
        : Buffer.alloc(0);
      if (bytes.byteLength > maxBytes) {
        return toResult(payloadTooLargeReply(maxBytes));
      }
      const rawBody = bytes.toString("utf-8");

      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(event.headers ?? {})) {
        if (value !== undefined) headers[key.toLowerCase()] = value;
      }

      const result: VerificationResult<ResolveEvent<TEvent, P>> =
        await verifyWebhook<TEvent, P>(
          provider,
          {
            headers,
            rawBody,
            url: eventUrl(event, headers),
            method: event.requestContext?.http?.method ?? event.httpMethod,
          },
          resolvedSecret,
          options,
        );

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, event);
        }
        return toResult(failureReply(result));
      }

      let handlerResult: LambdaHttpResult | void;
      try {
        handlerResult = await handler(
          parsePayload(rawBody),
          result,
          event,
          context,
        );
      } catch (handlerErr) {
        // Forget the event so the provider's retry is processed, not rejected as a duplicate.
        await releaseDedupeKey(result, options);
        throw handlerErr;
      }

      if (handlerResult) {
        if (handlerResult.statusCode >= 500) {
          await releaseDedupeKey(result, options);
        }
        return handlerResult;
      }
      return toResult({ status: 200, body: { received: true } });
    } catch (err: unknown) {
      if (options?.onError) {
        return await options.onError(exceptionResult(provider, err), event);
      }
      return toResult(INTERNAL_ERROR_REPLY);
    }
  };
}
