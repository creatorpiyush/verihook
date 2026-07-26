import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyDiscord } from '../src/index.js';

describe('Discord Interactions Verifier', () => {
  const timestamp = 1700000000;
  const body = JSON.stringify({ type: 1 }); // Discord PING interaction

  it('should verify a valid Ed25519 Discord interaction signature', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicSpkiDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const publicKeyHex = publicSpkiDer.subarray(publicSpkiDer.length - 32).toString('hex');

    const signatureBytes = sign(null, Buffer.from(`${timestamp}${body}`, 'utf-8'), privateKey);

    const req = {
      headers: {
        'x-signature-ed25519': signatureBytes.toString('hex'),
        'x-signature-timestamp': String(timestamp),
      },
      body,
    };

    const res = await verifyDiscord(req, publicKeyHex, { now: timestamp, tolerance: 300 });
    expect(res.valid).toBe(true);
    expect(res.provider).toBe('discord');
  });

  it('should reject missing Ed25519 signature or timestamp headers', async () => {
    const req = { headers: {}, body };
    const res = await verifyDiscord(req, 'pubkey');
    expect(res.valid).toBe(false);
    expect(res.code).toBe('MISSING_HEADER');
  });

  it('should reject expired Discord timestamp', async () => {
    const req = {
      headers: {
        'x-signature-ed25519': 'abc',
        'x-signature-timestamp': String(timestamp),
      },
      body,
    };

    const res = await verifyDiscord(req, 'pubkey', { now: timestamp + 500, tolerance: 300 });
    expect(res.valid).toBe(false);
    expect(res.code).toBe('EXPIRED_TIMESTAMP');
  });
});
