import { describe, expect, it, vi } from 'vitest';
import { computeHmacSha256 } from '../src/core/crypto.js';
import { verihookExpress } from '../src/express.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Express Middleware (verihookExpress)', () => {
  const secret = 'stripe_express_secret';
  const bodyObj = { id: 'evt_express_1', type: 'charge.succeeded' };
  const bodyStr = JSON.stringify(bodyObj);
  const timestamp = 1700000000;

  async function makeSignedHeader() {
    const payloadToSign = `${timestamp}.${bodyStr}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = bytesToHex(hmac);
    return `t=${timestamp},v1=${signature}`;
  }

  function mockRes() {
    const res: any = {};
    res.statusCode = 200;
    res.status = vi.fn().mockImplementation((code: number) => {
      res.statusCode = code;
      return res;
    });
    res.json = vi.fn().mockImplementation((data: any) => {
      res.body = data;
      return res;
    });
    return res;
  }

  it('should successfully verify request and call next() with attached verihook payload', async () => {
    const header = await makeSignedHeader();
    const middleware = verihookExpress('stripe', secret, { now: timestamp });

    const req: any = {
      headers: { 'stripe-signature': header },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(req.verihook).toBeDefined();
    expect(req.verihook.valid).toBe(true);
    expect(req.verihook.provider).toBe('stripe');
    expect(req.verihook.payload).toEqual(bodyObj);
    expect(req.verifiedPayload).toEqual(bodyObj);
  });

  it('should return 401 status and error JSON when signature is invalid', async () => {
    const middleware = verihookExpress('stripe', secret, { now: timestamp });

    const req: any = {
      headers: { 'stripe-signature': 't=1700000000,v1=bad_sig' },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.body).toEqual({
      error: 'Signature mismatch',
      code: 'INVALID_SIGNATURE',
    });
  });

  it('should invoke custom onError handler when verification fails', async () => {
    const onError = vi.fn().mockImplementation((result, _req, res) => {
      res.status(403).json({ custom: result.reason });
    });

    const middleware = verihookExpress('stripe', secret, { onError, now: timestamp });

    const req: any = {
      headers: {},
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(onError).toHaveBeenCalledTimes(1);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body).toEqual({ custom: 'Missing "stripe-signature" header' });
  });

  it('should resolve dynamic secret function based on request', async () => {
    const header = await makeSignedHeader();
    const secretResolver = vi.fn().mockImplementation((req: any) => {
      expect(req.tenantId).toBe('tenant_abc');
      return secret;
    });

    const middleware = verihookExpress('stripe', secretResolver, { now: timestamp });

    const req: any = {
      tenantId: 'tenant_abc',
      headers: { 'stripe-signature': header },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(secretResolver).toHaveBeenCalledWith(req);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.verihook.valid).toBe(true);
  });
});
