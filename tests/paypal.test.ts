import { describe, expect, it } from 'vitest';
import { computeCrc32, computeHmacSha256 } from '../src/core/crypto.js';
import { verifyPayPal } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('PayPal Webhook Verifier', () => {
  const secret = 'paypal_secret_key_123';
  const webhookId = 'WH-1234567890';
  const body = JSON.stringify({ event_type: 'PAYMENT.CAPTURE.COMPLETED', id: 'WH-EVT-100' });
  const transId = 'trans_123';
  const transTime = '2026-07-26T12:00:00Z';

  it('should calculate accurate CRC32 and verify PayPal signature using fallback mode', async () => {
    const crc = computeCrc32(body);
    const expectedPayload = `${transId}|${transTime}|${webhookId}|${crc}`;
    const hmac = await computeHmacSha256(secret, expectedPayload);
    const signature = bytesToHex(hmac);

    const req = {
      headers: {
        'paypal-transmission-id': transId,
        'paypal-transmission-time': transTime,
        'paypal-transmission-sig': signature,
      },
      body,
    };

    const result = await verifyPayPal(req, secret, { webhookId });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('paypal');
  });

  it('should reject missing PayPal transmission headers', async () => {
    const req = { headers: {}, body };
    const result = await verifyPayPal(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_HEADER');
  });
});
