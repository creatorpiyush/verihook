import { describe, expect, it } from 'vitest';
import { normalizeBody, normalizeHeaders, normalizeRequest } from '../src/utils/normalize-request.js';

describe('normalizeRequest & Utilities', () => {
  it('should normalize plain object headers with lowercasing', () => {
    const headers = normalizeHeaders({
      'Stripe-Signature': 't=123,v1=abc',
      'Content-Type': 'application/json',
      'X-ARRAY-HEADER': ['val1', 'val2'],
    });

    expect(headers['stripe-signature']).toBe('t=123,v1=abc');
    expect(headers['content-type']).toBe('application/json');
    expect(headers['x-array-header']).toBe('val1, val2');
  });

  it('should normalize Fetch API Headers', () => {
    const fetchHeaders = new Headers();
    fetchHeaders.set('X-Hub-Signature-256', 'sha256=abcdef');
    fetchHeaders.set('Content-Type', 'text/plain');

    const headers = normalizeHeaders(fetchHeaders);
    expect(headers['x-hub-signature-256']).toBe('sha256=abcdef');
    expect(headers['content-type']).toBe('text/plain');
  });

  it('should normalize body from string, Uint8Array, Buffer, and explicit raw object', () => {
    expect(normalizeBody('hello world')).toBe('hello world');
    expect(normalizeBody(new TextEncoder().encode('hello bytes'))).toBe('hello bytes');
    expect(normalizeBody({ key: 'value' }, true)).toBe('{"key":"value"}');
    expect(normalizeBody(Buffer.from('hello buffer'))).toBe('hello buffer');
  });

  it('should throw when plain object is passed without rawBody', () => {
    expect(() => normalizeBody({ key: 'value' })).toThrow('Parsed object passed as request body without rawBody');
  });

  it('should normalize standard Web Fetch Request objects', async () => {
    const req = new Request('https://example.com/webhook', {
      method: 'POST',
      headers: {
        'x-slack-signature': 'v0=123456',
        'x-slack-request-timestamp': '1600000000',
      },
      body: JSON.stringify({ event: 'user_created' }),
    });

    const normalized = await normalizeRequest(req);
    expect(normalized.headers['x-slack-signature']).toBe('v0=123456');
    expect(normalized.rawBody).toBe('{"event":"user_created"}');
    expect(normalized.url).toBe('https://example.com/webhook');
    expect(normalized.method).toBe('POST');
  });

  it('should normalize Express/Next.js req objects', async () => {
    const mockReq = {
      headers: {
        'X-Shopify-Hmac-SHA256': 'base64sig==',
      },
      rawBody: 'raw payload string',
      originalUrl: '/api/webhooks/shopify',
    };

    const normalized = await normalizeRequest(mockReq);
    expect(normalized.headers['x-shopify-hmac-sha256']).toBe('base64sig==');
    expect(normalized.rawBody).toBe('raw payload string');
    expect(normalized.url).toBe('/api/webhooks/shopify');
  });
});
