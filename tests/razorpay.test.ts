import { describe, expect, it } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verifyRazorpay } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Razorpay Webhook Verifier', () => {
  const secret = 'razorpay_secret_111';
  const body = JSON.stringify({ entity: 'event', event: 'payment.captured' });

  it('should verify valid Razorpay signature', async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = bytesToHex(hmac);

    const req = {
      headers: { 'x-razorpay-signature': signature },
      body,
    };

    const result = await verifyRazorpay(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('razorpay');
  });
});
