import { describe, expect, it } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verifyWebflow } from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Webflow Webhook Verifier', () => {
  const secret = 'webflow_secret_key_333';
  const timestamp = 1700000000;
  const body = JSON.stringify({ triggerType: 'form_submission' });

  it('should verify valid Webflow signature with timestamp header', async () => {
    const payloadToSign = `${timestamp}:${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = `sha256=${bytesToHex(hmac)}`;

    const req = {
      headers: {
        'x-webflow-signature': signature,
        'x-webflow-timestamp': String(timestamp),
      },
      body,
    };

    const result = await verifyWebflow(req, secret, { now: timestamp + 2 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('webflow');
  });

  it('should reject missing signature header', async () => {
    const req = { headers: {}, body };
    const result = await verifyWebflow(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_HEADER');
  });
});
