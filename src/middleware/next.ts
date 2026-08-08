import type {
  ProviderName,
  VerificationResult,
  VerifyWebhookOptions,
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
  return async (req: Request, ..._extraArgs: unknown[]): Promise<Response> => {
    try {
      const resolvedSecret =
        typeof secret === "function" ? await secret(req) : secret;
      const result = await verifyWebhook(
        provider,
        req,
        resolvedSecret,
        options,
      );

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, req);
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

      // Extract verified payload by cloning Request
      let payload: unknown;
      try {
        const clonedReq = req.clone();
        const text = await clonedReq.text();
        try {
          payload = JSON.parse(text);
        } catch {
          payload = text;
        }
      } catch {
        payload = null;
      }

      const handlerResult = await handler(payload, result, req);

      if (handlerResult instanceof Response) {
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

      return new Response(JSON.stringify({ error: errorMsg }), {
        status: 500,
        headers: standardSecurityHeaders,
      });
    }
  };
}
