import { releaseDedupeKey } from "../core/dedupe.js";
import {
  WebhookErrorCode,
  type ProviderName,
  type VerificationResult,
  type VerifyWebhookOptions,
} from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";
import type { SecretResolver } from "./express.js";

export interface VerihookNextOptions extends VerifyWebhookOptions {
  /**
   * Custom error handler function invoked when signature verification fails.
   */
  onError?: (
    result: VerificationResult,
    req: Request,
  ) => Response | Promise<Response>;
}

export type NextWebhookCallback = (
  payload: unknown,
  result: VerificationResult,
  req: Request,
) => Promise<Response | void> | Response | void;

const standardSecurityHeaders = {
  "Content-Type": "application/json",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

class PayloadTooLargeError extends Error {}

/**
 * Reads the request body as UTF-8, aborting once it exceeds `maxBytes`.
 */
async function readBodyWithLimit(
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
 * Next.js App Router & Web API Route Handler Factory for 1-line webhook verification.
 * Automatically verifies signatures, parses request payloads, executes callback logic,
 * and returns standardized HTTP responses with security headers.
 */
export function createWebhookHandler(
  provider: ProviderName,
  secret: SecretResolver<Request>,
  handler: NextWebhookCallback,
  options?: VerihookNextOptions,
) {
  const maxBytes = options?.maxBodySize ?? 2 * 1024 * 1024; // 2MB default

  return async (req: Request, ..._extraArgs: unknown[]): Promise<Response> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(req) : secret;

      let rawBody: string;
      try {
        rawBody = await readBodyWithLimit(req.clone(), maxBytes);
      } catch (err) {
        if (!(err instanceof PayloadTooLargeError)) throw err;
        return new Response(
          JSON.stringify({
            error: `Payload size exceeds limit of ${maxBytes} bytes`,
            code: "PAYLOAD_TOO_LARGE",
          }),
          { status: 413, headers: standardSecurityHeaders },
        );
      }

      const result = await verifyWebhook(
        provider,
        { headers: req.headers, rawBody, url: req.url, method: req.method },
        resolvedSecret,
        options,
      );

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, req);
        }
        // Acknowledge duplicates with 2xx so the provider stops retrying them.
        if (result.code === WebhookErrorCode.DUPLICATE_EVENT) {
          return new Response(
            JSON.stringify({ received: true, duplicate: true }),
            { status: 200, headers: standardSecurityHeaders },
          );
        }
        return new Response(
          JSON.stringify({
            error: result.reason,
            code: result.code,
          }),
          {
            status: 401,
            headers: standardSecurityHeaders,
          },
        );
      }

      let payload: unknown;
      try {
        payload = JSON.parse(rawBody);
      } catch {
        payload = rawBody;
      }

      let handlerResult: Response | void;
      try {
        handlerResult = await handler(payload, result, req);
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

      return new Response(JSON.stringify({ received: true }), {
        status: 200,
        headers: standardSecurityHeaders,
      });
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
        return await options.onError(errorResult, req);
      }

      // Details stay server-side (onError / telemetry); clients get a generic message.
      return new Response(
        JSON.stringify({ error: "Internal webhook verification error" }),
        {
          status: 500,
          headers: standardSecurityHeaders,
        },
      );
    }
  };
}
