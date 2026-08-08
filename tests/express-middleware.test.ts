import { describe, expect, it, vi } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verihookExpress } from "../src/express.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Express Middleware (verihookExpress)", () => {
  const secret = "stripe_express_secret";
  const bodyObj = { id: "evt_express_1", type: "charge.succeeded" };
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
    res.setHeader = vi.fn();
    return res;
  }

  it("should successfully verify request and call next() with attached verihook payload", async () => {
    const header = await makeSignedHeader();
    const middleware = verihookExpress("stripe", secret, { now: timestamp });

    const req: any = {
      headers: { "stripe-signature": header },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
    expect(req.verihook).toBeDefined();
    expect(req.verihook.valid).toBe(true);
    expect(req.verihook.provider).toBe("stripe");
    expect(req.verihook.payload).toEqual(bodyObj);
    expect(req.verifiedPayload).toEqual(bodyObj);
  });

  it("should verify request using req.rawBody when req.body is an object or Buffer", async () => {
    const header = await makeSignedHeader();
    const middleware = verihookExpress("stripe", secret, { now: timestamp });

    const reqBuffer: any = {
      headers: { "stripe-signature": header },
      rawBody: Buffer.from(bodyStr),
    };
    const resBuffer = mockRes();
    const nextBuffer = vi.fn();

    await middleware(reqBuffer, resBuffer, nextBuffer);
    expect(nextBuffer).toHaveBeenCalledTimes(1);
    expect(reqBuffer.verihook.valid).toBe(true);
    expect(reqBuffer.verihook.payload).toEqual(bodyObj);

    const reqObjectWithRaw: any = {
      headers: { "stripe-signature": header },
      body: bodyObj,
      rawBody: bodyStr,
    };
    const resObject = mockRes();
    const nextObject = vi.fn();

    await middleware(reqObjectWithRaw, resObject, nextObject);
    expect(nextObject).toHaveBeenCalledTimes(1);
    expect(reqObjectWithRaw.verihook.payload).toEqual(bodyObj);
  });

  it("should return 401 status and error JSON when signature is invalid", async () => {
    const middleware = verihookExpress("stripe", secret, { now: timestamp });

    const req: any = {
      headers: { "stripe-signature": "t=1700000000,v1=bad_sig" },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.body).toEqual({
      error: "Signature mismatch",
      code: "INVALID_SIGNATURE",
    });
  });

  it("should delegate error to next(result) when respondOnError is set to false", async () => {
    const middleware = verihookExpress("stripe", secret, {
      respondOnError: false,
      now: timestamp,
    });

    const req: any = {
      headers: { "stripe-signature": "t=1700000000,v1=bad_sig" },
      body: bodyStr,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0][0].valid).toBe(false);
  });

  it("should handle runtime exceptions with HTTP 500 or onError", async () => {
    const throwingSecretResolver = () => {
      throw new Error("Database connection failed");
    };

    const middleware500 = verihookExpress("stripe", throwingSecretResolver);
    const req500: any = { headers: {} };
    const res500 = mockRes();
    const next500 = vi.fn();

    await middleware500(req500, res500, next500);
    expect(res500.status).toHaveBeenCalledWith(500);
    expect(res500.body).toEqual({ error: "Database connection failed" });

    const onError = vi.fn().mockImplementation((_result, _req, res) => {
      res.status(503).json({ error: "service unavailable" });
    });
    const middlewareCustom = verihookExpress("stripe", throwingSecretResolver, {
      onError,
    });
    const reqCustom: any = { headers: {} };
    const resCustom = mockRes();
    const nextCustom = vi.fn();

    await middlewareCustom(reqCustom, resCustom, nextCustom);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(resCustom.status).toHaveBeenCalledWith(503);

    const middlewarePassNext = verihookExpress(
      "stripe",
      throwingSecretResolver,
      { respondOnError: false },
    );
    const reqPassNext: any = { headers: {} };
    const resPassNext = mockRes();
    const nextPassNext = vi.fn();

    await middlewarePassNext(reqPassNext, resPassNext, nextPassNext);
    expect(nextPassNext).toHaveBeenCalledWith(expect.any(Error));
  });

  it("should handle unparseable non-JSON text bodies gracefully", async () => {
    const textBody = "plain_text_non_json_payload";
    const payloadToSign = `${timestamp}.${textBody}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = `t=${timestamp},v1=${bytesToHex(hmac)}`;

    const middleware = verihookExpress("stripe", secret, { now: timestamp });

    const req: any = {
      headers: { "stripe-signature": signature },
      body: textBody,
    };
    const res = mockRes();
    const next = vi.fn();

    await middleware(req, res, next);
    expect(req.verihook.payload).toBe(textBody);
    expect(req.verifiedPayload).toBe(textBody);

    const reqRaw: any = {
      headers: { "stripe-signature": signature },
      body: { not: "string" },
      rawBody: textBody,
    };
    const resRaw = mockRes();
    const nextRaw = vi.fn();

    await middleware(reqRaw, resRaw, nextRaw);
    expect(reqRaw.verihook.payload).toBe(textBody);
  });
});
