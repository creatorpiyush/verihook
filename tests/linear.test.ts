import { describe, expect, it } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verifyLinear } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Linear Webhook Verifier', () => {
  const secret = 'linear_secret_key_444';
  const body = JSON.stringify({ action: 'create', type: 'Issue' });

  it('should verify valid Linear signature', async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = bytesToHex(hmac);

    const req = {
      headers: { 'linear-signature': signature },
      body,
    };

    const result = await verifyLinear(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('linear');
  });
});
