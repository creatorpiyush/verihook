import { describe, expect, it } from 'vitest';
import {
  WebhookErrorCode,
  WebhookVerificationError,
  registerProvider,
  verifyClerk,
  verifyResend,
  verifyWebhook,
  verifyWebhookOrThrow,
} from '../src/index.js';

describe('Verifier Engine & Errors', () => {
  it('should return invalid result with INVALID_SECRET code when secret is missing', async () => {
    const result = await verifyWebhook('stripe', { headers: {}, body: 'raw' }, '');
    expect(result.valid).toBe(false);
    expect(result.code).toBe(WebhookErrorCode.INVALID_SECRET);
    expect(result.reason).toContain('secret is required');
  });

  it('should return UNSUPPORTED_PROVIDER code for unsupported provider name', async () => {
    const result = await verifyWebhook('unknown_provider' as any, { headers: {}, body: 'raw' }, 'secret');
    expect(result.valid).toBe(false);
    expect(result.code).toBe(WebhookErrorCode.UNSUPPORTED_PROVIDER);
    expect(result.reason).toContain('Unsupported provider');
  });

  it('should throw WebhookVerificationError with accurate code on signature failure', async () => {
    try {
      await verifyWebhookOrThrow('stripe', { headers: {}, body: 'raw' }, 'secret');
    } catch (err: any) {
      expect(err).toBeInstanceOf(WebhookVerificationError);
      expect(err.code).toBe(WebhookErrorCode.MISSING_HEADER);
      expect(err.provider).toBe('stripe');
    }
  });

  it('should support verifyResend and verifyClerk helpers', async () => {
    const req = { headers: {}, body: 'raw' };
    const resendRes = await verifyResend(req, 'secret');
    const clerkRes = await verifyClerk(req, 'secret');

    expect(resendRes.code).toBe(WebhookErrorCode.MISSING_HEADER);
    expect(clerkRes.code).toBe(WebhookErrorCode.MISSING_HEADER);
  });

  it('should fail fast with INVALID_BODY when plain object passed without rawBody', async () => {
    const result = await verifyWebhook('stripe', { headers: {}, body: { event: 'test' } }, 'secret');
    expect(result.valid).toBe(false);
    expect(result.code).toBe(WebhookErrorCode.INVALID_BODY);
    expect(result.reason).toContain('Parsed object passed as request body without rawBody');
    expect(result.error).toBeInstanceOf(Error);
  });

  it('should allow registering a custom provider plugin', async () => {
    registerProvider({
      name: 'my-plugin',
      async verify(req, secret) {
        return {
          valid: req.headers['x-plugin-sig'] === secret,
          provider: 'my-plugin',
        };
      },
    });

    const result = await verifyWebhook('my-plugin' as any, { headers: { 'x-plugin-sig': 'secret123' }, body: 'raw' }, 'secret123');
    expect(result.valid).toBe(true);
  });
});
