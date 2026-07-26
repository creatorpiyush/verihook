import { describe, expect, it } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verifySlack } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Slack Webhook Verifier', () => {
  const secret = 'slack_signing_secret_888';
  const body = 'token=gIOm5BIZJR0DZ3enR.123&team_id=T0001';
  const timestamp = 1700000000;

  it('should verify valid Slack signature', async () => {
    const sigBase = `v0:${timestamp}:${body}`;
    const hmac = await computeHmacSha256(secret, sigBase);
    const signature = `v0=${bytesToHex(hmac)}`;

    const req = {
      headers: {
        'x-slack-signature': signature,
        'x-slack-request-timestamp': String(timestamp),
      },
      body,
    };

    const result = await verifySlack(req, secret, { now: timestamp + 20 });
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(timestamp);
  });

  it('should reject when timestamp is expired outside tolerance window', async () => {
    const req = {
      headers: {
        'x-slack-signature': 'v0=abc',
        'x-slack-request-timestamp': String(timestamp),
      },
      body,
    };

    const result = await verifySlack(req, secret, { now: timestamp + 500, tolerance: 300 });
    expect(result.valid).toBe(false);
    expect(result.code).toBe('EXPIRED_TIMESTAMP');
    expect(result.reason).toContain('Timestamp outside tolerance window');
  });

  it('should reject when timestamp header is missing', async () => {
    const req = {
      headers: { 'x-slack-signature': 'v0=abc' },
      body,
    };
    const result = await verifySlack(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_HEADER');
    expect(result.reason).toContain('Missing "x-slack-request-timestamp" header');
  });
});
