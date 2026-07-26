import { describe, expect, it } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verifyWorkOS } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('WorkOS Webhook Verifier', () => {
  const secret = 'workos_secret_key_444';
  const timestamp = 1700000000;
  const body = JSON.stringify({ event: 'user.created' });

  it('should verify valid WorkOS signature', async () => {
    const payloadToSign = `${timestamp}.${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = `t=${timestamp},v1=${bytesToHex(hmac)}`;

    const req = {
      headers: { 'workos-signature': signature },
      body,
    };

    const result = await verifyWorkOS(req, secret, { now: timestamp + 2 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('workos');
  });

  it('should reject invalid signature format', async () => {
    const req = {
      headers: { 'workos-signature': 'invalid_format' },
      body,
    };

    const result = await verifyWorkOS(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_HEADER');
  });
});
