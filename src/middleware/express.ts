import type { ProviderName, VerificationResult, VerifyWebhookOptions } from '../core/types.js';
import { verifyWebhook } from '../core/verifier.js';

export type SecretResolver<Req = any> = string | ((req: Req) => string | Promise<string>);

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
    req: any,
    res: any,
    next: any
  ) => void | Promise<void>;
}

export interface VerihookRequestAdditions {
  verihook?: {
    valid: boolean;
    provider: ProviderName;
    payload: any;
    timestamp?: number;
    result: VerificationResult;
  };
  verifiedPayload?: any;
}

/**
 * Express middleware for 1-line webhook verification.
 * Automatically validates signature, parses payload, attaches req.verihook & req.verifiedPayload,
 * and handles error responses.
 */
export function verihookExpress(
  provider: ProviderName,
  secret: SecretResolver,
  options?: VerihookExpressOptions
) {
  return async (req: any, res: any, next: any) => {
    try {
      const resolvedSecret = typeof secret === 'function' ? await secret(req) : secret;

      // Handle unparsed body stream if req.body is undefined and stream is available
      if (req.body === undefined && typeof req.on === 'function') {
        const chunks: Uint8Array[] = [];
        for await (const chunk of req) {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        }
        const rawBuffer = Buffer.concat(chunks);
        req.rawBody = rawBuffer.toString('utf-8');
        req.body = req.rawBody;
      }

      const result = await verifyWebhook(provider, req, resolvedSecret, options);

      if (!result.valid) {
        if (options?.onError) {
          return await options.onError(result, req, res, next);
        }

        if (options?.respondOnError !== false) {
          return res.status(401).json({
            error: result.reason,
            code: result.code,
          });
        }
        return next(result);
      }

      // Extract / parse verified payload
      let payload: any = req.body;
      if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
        const bodyStr = req.body.toString('utf-8');
        try {
          payload = JSON.parse(bodyStr);
        } catch {
          payload = bodyStr;
        }
      } else if (req.rawBody && (typeof req.rawBody === 'string' || Buffer.isBuffer(req.rawBody))) {
        const bodyStr = req.rawBody.toString('utf-8');
        try {
          payload = JSON.parse(bodyStr);
        } catch {
          payload = bodyStr;
        }
      }

      req.verihook = {
        valid: true,
        provider,
        payload,
        timestamp: result.timestamp,
        result,
      };
      req.verifiedPayload = payload;

      next();
    } catch (err: any) {
      const errorResult: VerificationResult = {
        valid: false,
        provider,
        reason: err.message || 'Verification exception',
        error: err,
      };

      if (options?.onError) {
        return await options.onError(errorResult, req, res, next);
      }
      if (options?.respondOnError !== false) {
        return res.status(500).json({ error: err.message || 'Internal Server Error' });
      }
      next(err);
    }
  };
}
