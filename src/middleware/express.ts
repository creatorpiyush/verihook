import { releaseDedupeKey } from "../core/dedupe.js";
import {
  WebhookErrorCode,
  type ProviderName,
  type VerificationResult,
  type VerifyWebhookOptions,
} from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";

export interface ExpressRequestLike {
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: string | Uint8Array | ArrayBuffer;
  url?: string;
  originalUrl?: string;
  method?: string;
  protocol?: string;
  on?: (event: string, listener: (...args: unknown[]) => void) => void;
}

export interface ExpressResponseLike {
  status(code: number): this;
  json(body: unknown): this;
  setHeader(name: string, value: string): this;
  statusCode?: number;
  on?(event: string, listener: () => void): unknown;
}

export type ExpressNextLike = (err?: unknown) => void;

export type SecretResolver<Req = ExpressRequestLike> =
  string | ((req: Req) => string | Promise<string>);

export interface VerihookExpressOptions extends VerifyWebhookOptions {
  /**
   * Whether to automatically send an HTTP 401 response on signature verification failure.
   * @default true
   */
  respondOnError?: boolean;

  /**
   * Custom error handler function invoked when signature verification fails or throws.
   */
  onError?: (
    result: VerificationResult,
    req: ExpressRequestLike,
    res: ExpressResponseLike,
    next: ExpressNextLike,
  ) => void | Promise<void>;
}

/**
 * Fields the middleware adds to the request. Pass the payload type for a typed
 * `event`, e.g. `req as Request & VerihookRequestAdditions<StripeEvent>`.
 */
export interface VerihookRequestAdditions<TEvent = unknown> {
  verihook?: {
    valid: boolean;
    provider: ProviderName;
    payload: unknown;
    /** Parsed payload (JSON, or form fields), same as `result.event`. */
    event?: TEvent;
    /** Event name, e.g. `"invoice.paid"`, same as `result.eventType`. */
    eventType?: string;
    timestamp?: number;
    result: VerificationResult<TEvent>;
  };
  verifiedPayload?: unknown;
}

function setSecurityHeaders(res: ExpressResponseLike): void {
  if (typeof res.setHeader === "function") {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
  }
}

/**
 * Express middleware for 1-line webhook verification.
 * Automatically validates signature, parses payload, attaches req.verihook & req.verifiedPayload,
 * and handles error responses with security headers and max payload size limits.
 */
export function verihookExpress(
  provider: ProviderName,
  secret: SecretResolver,
  options?: VerihookExpressOptions,
): (
  req: ExpressRequestLike,
  res: ExpressResponseLike,
  next: ExpressNextLike,
) => Promise<void> {
  const maxBytes = options?.maxBodySize ?? 2 * 1024 * 1024; // 2MB default

  return async (
    req: ExpressRequestLike,
    res: ExpressResponseLike,
    next: ExpressNextLike,
  ): Promise<void> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(req) : secret;

      // Handle unparsed body stream if req.body is undefined and stream is available
      if (req.body === undefined && typeof req.on === "function") {
        const chunks: Uint8Array[] = [];
        let totalBytes = 0;
        const asyncIterable = req as unknown as AsyncIterable<
          Uint8Array | string
        >;

        for await (const chunk of asyncIterable) {
          const bufferChunk =
            typeof chunk === "string" ? Buffer.from(chunk) : chunk;
          totalBytes += bufferChunk.length;
          if (totalBytes > maxBytes) {
            setSecurityHeaders(res);
            res.status(413).json({
              error: `Payload size exceeds limit of ${maxBytes} bytes`,
              code: "PAYLOAD_TOO_LARGE",
            });
            return;
          }
          chunks.push(bufferChunk);
        }
        const rawBuffer = Buffer.concat(chunks);
        req.rawBody = rawBuffer.toString("utf-8");
        req.body = req.rawBody;
      }

      const result = await verifyWebhook(
        provider,
        req as unknown as Parameters<typeof verifyWebhook>[1],
        resolvedSecret,
        options,
      );

      if (!result.valid) {
        if (options?.onError) {
          await options.onError(result, req, res, next);
          return;
        }

        if (options?.respondOnError !== false) {
          setSecurityHeaders(res);
          // Acknowledge duplicates with 2xx so the provider stops retrying them.
          if (result.code === WebhookErrorCode.DUPLICATE_EVENT) {
            res.status(200).json({ received: true, duplicate: true });
            return;
          }
          res.status(401).json({
            error: result.reason,
            code: result.code,
          });
          return;
        }
        return next(result);
      }

      // Extract / parse verified payload
      let payload: unknown = req.body;
      if (typeof req.body === "string" || Buffer.isBuffer(req.body)) {
        const bodyStr = req.body.toString("utf-8");
        try {
          payload = JSON.parse(bodyStr);
        } catch {
          payload = bodyStr;
        }
      } else if (
        req.rawBody &&
        (typeof req.rawBody === "string" || Buffer.isBuffer(req.rawBody))
      ) {
        const bodyStr = req.rawBody.toString("utf-8");
        try {
          payload = JSON.parse(bodyStr);
        } catch {
          payload = bodyStr;
        }
      }

      (req as unknown as VerihookRequestAdditions).verihook = {
        valid: true,
        provider,
        payload,
        event: result.event,
        eventType: result.eventType,
        timestamp: result.timestamp,
        result,
      };
      (req as unknown as VerihookRequestAdditions).verifiedPayload = payload;

      // If downstream processing fails, forget the event so the provider's retry is handled.
      if (result.dedupeKey && typeof res.on === "function") {
        res.on("finish", () => {
          if ((res.statusCode ?? 200) >= 500) {
            void releaseDedupeKey(result, options);
          }
        });
      }

      next();
    } catch (err: unknown) {
      const errorMsg =
        err instanceof Error ? err.message : "Verification exception";
      const errorResult: VerificationResult = {
        valid: false,
        provider,
        reason: errorMsg,
        error: err instanceof Error ? err : new Error(String(err)),
      };

      if (options?.onError) {
        await options.onError(errorResult, req, res, next);
        return;
      }
      if (options?.respondOnError !== false) {
        setSecurityHeaders(res);
        // Details stay server-side (onError / telemetry); clients get a generic message.
        res.status(500).json({ error: "Internal webhook verification error" });
        return;
      }
      next(err);
    }
  };
}
