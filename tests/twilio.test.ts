import { describe, expect, it } from 'vitest';
import { computeHmacSha1, computeSha256 } from '../src/core/crypto.js';
import { verifyTwilio } from '../src/index.js';
import { bytesToBase64, bytesToHex } from '../src/utils/encoding.js';

describe('Twilio Webhook Verifier', () => {
  const secret = 'twilio_auth_token_777';
  const url = 'https://mycompany.com/twilio/voice';
  const formBody = 'CallSid=CA12345&From=%2B14155551212&To=%2B14155555555';
  const jsonBody = JSON.stringify({ messageSid: 'MM123', status: 'delivered' });

  it('should verify valid Twilio form-urlencoded signature with sorted params', async () => {
    const dataToSign = `${url}CallSidCA12345From+14155551212To+14155555555`;
    const hmac = await computeHmacSha1(secret, dataToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: {
        'x-twilio-signature': signature,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: formBody,
      url,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('twilio');
  });

  it('should verify valid Twilio JSON signature with bodySHA256', async () => {
    const hashBytes = await computeSha256(jsonBody);
    const hashHex = bytesToHex(hashBytes).toLowerCase();
    const dataToSign = `${url}?bodySHA256=${encodeURIComponent(hashHex)}`;

    const hmac = await computeHmacSha1(secret, dataToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: {
        'x-twilio-signature': signature,
        'content-type': 'application/json',
      },
      body: jsonBody,
      url,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('twilio');
  });

  it('should verify form payload when content-type header is missing', async () => {
    const dataToSign = `${url}CallSidCA12345From+14155551212To+14155555555`;
    const hmac = await computeHmacSha1(secret, dataToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: {
        'x-twilio-signature': signature,
      },
      body: formBody,
      url,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('twilio');
  });

  it('should replace existing bodySHA256 in URL instead of appending duplicates', async () => {
    const urlWithExistingBodyHash = `${url}?foo=1&bodySHA256=stale`;
    const hashBytes = await computeSha256(jsonBody);
    const hashHex = bytesToHex(hashBytes).toLowerCase();

    const canonicalUrl = new URL(urlWithExistingBodyHash);
    canonicalUrl.searchParams.set('bodySHA256', hashHex);
    const dataToSign = canonicalUrl.toString();

    const hmac = await computeHmacSha1(secret, dataToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: {
        'x-twilio-signature': signature,
        'content-type': 'application/json',
      },
      body: jsonBody,
      url: urlWithExistingBodyHash,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe('twilio');
  });

  it('should fail when URL is missing', async () => {
    const req = {
      headers: { 'x-twilio-signature': 'sig==' },
      body: formBody,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_URL');
    expect(result.reason).toContain('Missing request URL');
  });

  it('should verify form payloads containing repeated parameter key names', async () => {
    const multiValBody = 'tag=alpha&tag=beta';
    const dataToSign = `${url}tagalphatagbeta`;
    const hmac = await computeHmacSha1(secret, dataToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: {
        'x-twilio-signature': signature,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: multiValBody,
      url,
    };

    const result = await verifyTwilio(req, secret);
    expect(result.valid).toBe(true);
  });
});
