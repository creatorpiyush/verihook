import { describe, expect, it, vi } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { createWebhookHandler } from '../src/next.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Next.js Route Handler Factory (createWebhookHandler)', () => {
  const secret = 'github_next_secret';
  const bodyObj = { action: 'opened', issue: { id: 42, title: 'Bug report' } };
  const bodyStr = JSON.stringify(bodyObj);

  async function makeGitHubSignature() {
    const hmac = await computeHmacSha256(secret, bodyStr);
    return `sha256=${bytesToHex(hmac)}`;
  }

  it('should successfully verify request and call inner handler', async () => {
    const signature = await makeGitHubSignature();
    const mockHandler = vi.fn().mockResolvedValue(undefined);

    const routeHandler = createWebhookHandler('github', secret, mockHandler);

    const req = new Request('https://example.com/api/webhooks/github', {
      method: 'POST',
      headers: {
        'x-hub-signature-256': signature,
        'content-type': 'application/json',
      },
      body: bodyStr,
    });

    const response = await routeHandler(req);

    expect(mockHandler).toHaveBeenCalledTimes(1);
    const [payload, result, requestArg] = mockHandler.mock.calls[0];
    expect(payload).toEqual(bodyObj);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('github');
    expect(requestArg).toBe(req);

    expect(response.status).toBe(200);
    const json = await response.json();
    expect(json).toEqual({ received: true });
  });

  it('should return custom Response if inner handler returns a Response', async () => {
    const signature = await makeGitHubSignature();
    const routeHandler = createWebhookHandler('github', secret, async (payload) => {
      return new Response(JSON.stringify({ processedIssueId: payload.issue.id }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    const req = new Request('https://example.com/api/webhooks/github', {
      method: 'POST',
      headers: { 'x-hub-signature-256': signature },
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(response.status).toBe(202);
    const json = await response.json();
    expect(json).toEqual({ processedIssueId: 42 });
  });

  it('should return 401 Response on invalid signature', async () => {
    const mockHandler = vi.fn();
    const routeHandler = createWebhookHandler('github', secret, mockHandler);

    const req = new Request('https://example.com/api/webhooks/github', {
      method: 'POST',
      headers: { 'x-hub-signature-256': 'sha256=invalid_sig' },
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(mockHandler).not.toHaveBeenCalled();
    expect(response.status).toBe(401);
    const json = await response.json();
    expect(json).toEqual({
      error: 'SHA-256 signature mismatch',
      code: 'INVALID_SIGNATURE',
    });
  });

  it('should invoke custom onError handler on signature failure', async () => {
    const routeHandler = createWebhookHandler(
      'github',
      secret,
      vi.fn(),
      {
        onError: async (result) => {
          return new Response(JSON.stringify({ customError: result.reason }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          });
        },
      }
    );

    const req = new Request('https://example.com/api/webhooks/github', {
      method: 'POST',
      headers: {},
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json).toEqual({ customError: 'Missing "x-hub-signature-256" or "x-hub-signature" header' });
  });

  it('should resolve dynamic secret callback based on request headers/URL', async () => {
    const signature = await makeGitHubSignature();
    const secretResolver = vi.fn().mockResolvedValue(secret);

    const routeHandler = createWebhookHandler('github', secretResolver, async () => {});

    const req = new Request('https://example.com/api/webhooks/github', {
      method: 'POST',
      headers: { 'x-hub-signature-256': signature },
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(secretResolver).toHaveBeenCalledWith(req);
    expect(response.status).toBe(200);
  });
});
