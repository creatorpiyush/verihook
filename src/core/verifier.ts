import { getProviderVerifier } from '../providers/index.js';
import { normalizeRequest } from '../utils/normalize-request.js';
import { WebhookVerificationError } from './errors.js';
import {
  ProviderName,
  VerificationErrorCode,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
  WebhookRequestInput,
} from './types.js';

/**
 * Universal webhook verification function.
 * Normalizes input request formats (Fetch Request, Express req, Next.js, Fastify, custom)
 * and verifies signature against provider specification.
 *
 * @returns VerificationResult containing valid status, error code, reason, timestamp, and optional raw error.
 */
export async function verifyWebhook(
  provider: ProviderName,
  req: WebhookRequestInput,
  secret: string,
  options?: VerifyWebhookOptions
): Promise<VerificationResult> {
  if (!secret) {
    return {
      valid: false,
      provider,
      code: WebhookErrorCode.INVALID_SECRET,
      reason: 'Webhook secret is required',
    };
  }

  try {
    const verifier = getProviderVerifier(provider);
    const normalizedReq = await normalizeRequest(req);
    return await verifier.verify(normalizedReq, secret, options);
  } catch (err: any) {
    const code: VerificationErrorCode = err?.code || WebhookErrorCode.UNKNOWN_ERROR;

    return {
      valid: false,
      provider,
      code,
      reason: err?.message || 'Unknown verification error',
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }
}

/**
 * Universal webhook verification function that throws `WebhookVerificationError`
 * if verification fails.
 *
 * @throws WebhookVerificationError when verification fails.
 */
export async function verifyWebhookOrThrow(
  provider: ProviderName,
  req: WebhookRequestInput,
  secret: string,
  options?: VerifyWebhookOptions
): Promise<VerificationResult> {
  const result = await verifyWebhook(provider, req, secret, options);
  if (!result.valid) {
    throw new WebhookVerificationError(
      result.provider,
      result.reason || 'Verification failed',
      result.code || WebhookErrorCode.INVALID_SIGNATURE
    );
  }
  return result;
}

// Provider-specific helper shortcuts
export const verifyStripe = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('stripe', req, secret, opts);

export const verifyGitHub = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('github', req, secret, opts);

export const verifyShopify = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('shopify', req, secret, opts);

export const verifySlack = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('slack', req, secret, opts);

export const verifyTwilio = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('twilio', req, secret, opts);

export const verifySvix = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('svix', req, secret, opts);

export const verifyResend = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('resend', req, secret, opts);

export const verifyClerk = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('clerk', req, secret, opts);

export const verifyLinear = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('linear', req, secret, opts);

export const verifyRazorpay = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('razorpay', req, secret, opts);

export const verifySquare = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('square', req, secret, opts);

export const verifyZoom = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('zoom', req, secret, opts);

export const verifyMeta = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('meta', req, secret, opts);

export const verifyWhatsApp = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('whatsapp', req, secret, opts);

export const verifyDiscord = (req: WebhookRequestInput, secret: string, opts?: VerifyWebhookOptions) =>
  verifyWebhook('discord', req, secret, opts);
