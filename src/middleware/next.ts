import type { ProviderName, VerificationResult, VerifyWebhookOptions } from '../core/types.js';
import { verifyWebhook } from '../core/verifier.js';
import type { SecretResolver } from './express.js';

export interface VerihookNextOptions extends VerifyWebhookOptions {
  /**
   * Custom error handler function invoked when signature verification fails.
   */
  onError?: (result: VerificationResult, req: Request) => Response | Promise<Response>;
}

export type NextWebhookCallback = (
  payload: any,
  result: VerificationResult,
  req: Request
) => Promise<Response | void> | Response | void;

/**
 * Next.js App Router & Web API Route Handler Factory for 1-line webhook verification.
 * Automatically verifies signatures, parses request payloads, executes callback logic,
 * and returns standardized HTTP responses.
 */
export function createWebhookHandler(
  provider: ProviderName,
  secret: SecretResolver<Request>,
  handler: NextWebhookCallback,
  options?: VerihookNextOptions
) {
  return async (req: Request, ..._extraArgs: any[]): Promise<Response> => {
    try {
      const resolvedSecret = typeof secret === 'function' ? await secret(req) : secret;
      const result = await verifyWebhook(provider, req, resolvedSecret, options);

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
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      // Extract verified payload by cloning Request
      let payload: any;
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
        headers: { 'Content-Type': 'application/json' },
      });
    } catch (err: any) {
      const errorResult: VerificationResult = {
        valid: false,
        provider,
        reason: err.message || 'Verification exception',
        error: err,
      };

      if (options?.onError) {
        return await options.onError(errorResult, req);
      }

      return new Response(
        JSON.stringify({ error: err.message || 'Internal Server Error' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
  };
}
