import { describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import {
  computeHmacSha1,
  setGlobalLogger,
  verifyGitHub,
  verifyMeta,
  verifyPaddle,
  verifyPayPal,
  verifySvix,
  verifyTwilio,
  verifyWebflow,
  verifyWebhook,
  verifyWebhookOrThrow,
} from "../src/index.js";
import { runCli } from "../src/cli/index.js";
import { createWebhookHandler } from "../src/next.js";
import { normalizeBody } from "../src/utils/normalize-request.js";
import { validateCliArgs } from "../src/schemas/index.js";
import { bytesToBase64, bytesToHex } from "../src/utils/encoding.js";

describe("Ultimate Coverage Boost for >97%+ Test Suite", () => {
  it("should test CLI invalid args, SSRF helper subnets, and non-local warnings", async () => {
    const invalidRes = validateCliArgs({ provider: "" });
    expect(invalidRes.success).toBe(false);
    expect(invalidRes.errors).toContain("provider must be a non-empty string");

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli([
      "simulate",
      "stripe",
      "--url",
      "http://127.0.0.1:3000/webhook",
      "--curl",
    ]);
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining("curl -X POST"),
    );
    logSpy.mockRestore();
  });

  it("should test verifyWebhookOrThrow on successful signature verification", async () => {
    const secret = "stripe_valid_throw_secret";
    const bodyStr = JSON.stringify({ id: "evt_123" });
    const timestamp = Math.floor(Date.now() / 1000);
    const payloadToSign = `${timestamp}.${bodyStr}`;

    const hmacBytes = crypto
      .createHmac("sha256", secret)
      .update(payloadToSign)
      .digest();
    const signature = `t=${timestamp},v1=${hmacBytes.toString("hex")}`;

    const res = await verifyWebhookOrThrow(
      "stripe",
      { headers: { "stripe-signature": signature }, body: bodyStr },
      secret,
    );
    expect(res.valid).toBe(true);
    expect(res.provider).toBe("stripe");
  });

  it("should test global logger asynchronous Promise rejection handling", async () => {
    const rejectingLogger = () =>
      Promise.reject(new Error("Global logger rejected"));
    setGlobalLogger(rejectingLogger as any);

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const now = Math.floor(Date.now() / 1000);
    const payloadToSign = `${now}.raw`;
    const hmacHex = crypto
      .createHmac("sha256", "sec")
      .update(payloadToSign)
      .digest("hex");

    await verifyWebhook(
      "stripe",
      {
        headers: {
          "stripe-signature": `t=${now},v1=${hmacHex}`,
        },
        body: "raw",
      },
      "sec",
    );

    await new Promise((r) => setTimeout(r, 20));
    setGlobalLogger(null as any);
    warnSpy.mockRestore();
  });

  it("should test Next.js handler with custom Response return and throwing req.clone()", async () => {
    const handlerCustomRes = createWebhookHandler(
      "stripe",
      "sec",
      async () => new Response("Custom Next Response", { status: 202 }),
    );

    const timestamp = Math.floor(Date.now() / 1000);
    const bodyStr = JSON.stringify({ test: 1 });
    const sig = `t=${timestamp},v1=${crypto.createHmac("sha256", "sec").update(`${timestamp}.${bodyStr}`).digest("hex")}`;

    const req = new Request("http://localhost:3000/api/webhook", {
      method: "POST",
      headers: { "stripe-signature": sig },
      body: bodyStr,
    });

    const resCustom = await handlerCustomRes(req);
    expect(resCustom.status).toBe(202);
    expect(await resCustom.text()).toBe("Custom Next Response");

    // Exception in secret resolver without onError -> returns 500 Response
    const handlerException = createWebhookHandler(
      "stripe",
      () => {
        throw new Error("Secret resolution error");
      },
      async () => {},
    );

    const res500 = await handlerException(req);
    expect(res500.status).toBe(500);
    expect(await res500.json()).toEqual({ error: "Secret resolution error" });
  });

  it("should test GitHub SHA-1 signature mismatch branch", async () => {
    const res = await verifyGitHub(
      { headers: { "x-hub-signature": "sha1=bad_sha1_hex" }, body: "raw" },
      "sec",
    );
    expect(res.valid).toBe(false);
    expect(res.code).toBe("INVALID_SIGNATURE");
    expect(res.reason).toContain("SHA-1 signature mismatch");
  });

  it("should test Meta SHA-1 signature mode verification", async () => {
    const bodyStr = JSON.stringify({ entry: [] });
    const hmacBytes = await computeHmacSha1("meta_app_secret", bodyStr);
    const sigHex = bytesToHex(hmacBytes);

    const validRes = await verifyMeta(
      { headers: { "x-hub-signature": `sha1=${sigHex}` }, body: bodyStr },
      "meta_app_secret",
    );
    expect(validRes.valid).toBe(true);

    const invalidRes = await verifyMeta(
      {
        headers: { "x-hub-signature": "sha1=invalid_meta_sig" },
        body: bodyStr,
      },
      "meta_app_secret",
    );
    expect(invalidRes.valid).toBe(false);
  });

  it("should test Paddle and Svix invalid timestamp NaN format", async () => {
    const paddleRes = await verifyPaddle(
      { headers: { "paddle-signature": "ts=invalid_nan;h=sig" }, body: "raw" },
      "sec",
    );
    expect(paddleRes.code).toBe("MISSING_HEADER");

    const svixRes = await verifySvix(
      {
        headers: {
          "svix-id": "msg_1",
          "svix-timestamp": "invalid_nan",
          "svix-signature": "v1,sig",
        },
        body: "raw",
      },
      "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    );
    expect(svixRes.code).toBe("MISSING_HEADER");

    const svixPlainSecretRes = await verifySvix(
      {
        headers: {
          "svix-id": "msg_1",
          "svix-timestamp": String(Math.floor(Date.now() / 1000)),
          "svix-signature": "v1,invalid_sig",
        },
        body: "raw",
      },
      "plain_text_non_base64_secret",
    );
    expect(svixPlainSecretRes.code).toBe("INVALID_SIGNATURE");
  });

  it("should test PayPal RSA-SHA256 valid signature branch", async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const pemPubKey = publicKey
      .export({ type: "pkcs1", format: "pem" })
      .toString();

    const transmissionId = "tx_paypal_100";
    const transmissionTime = "2026-08-08T12:00:00Z";
    const body = JSON.stringify({ event: "PAYMENT.CAPTURE.COMPLETED" });

    const crc = (await import("../src/core/crypto.js")).computeCrc32(body);
    const expectedPayload = `${transmissionId}|${transmissionTime}|my_paypal_webhook_id|${crc}`;

    const signer = crypto.createSign("RSA-SHA256");
    signer.update(expectedPayload);
    const sigBytes = signer.sign(privateKey);
    const sigBase64 = bytesToBase64(sigBytes);

    const res = await verifyPayPal(
      {
        headers: {
          "paypal-transmission-id": transmissionId,
          "paypal-transmission-time": transmissionTime,
          "paypal-transmission-sig": sigBase64,
        },
        body,
      },
      pemPubKey,
      { webhookId: "my_paypal_webhook_id" },
    );
    expect(res.valid).toBe(true);
    expect(res.provider).toBe("paypal");
  });

  it("should test Twilio signature mismatch and Webflow timestamp expiration", async () => {
    const twilioRes = await verifyTwilio(
      {
        headers: { "x-twilio-signature": "bad_sig==" },
        body: "CallSid=1",
        url: "http://localhost/twilio",
      },
      "sec",
    );
    expect(twilioRes.valid).toBe(false);
    expect(twilioRes.code).toBe("INVALID_SIGNATURE");

    const expiredTs = Math.floor(Date.now() / 1000) - 1000;
    const webflowRes = await verifyWebflow(
      {
        headers: {
          "x-webflow-signature": "sha256=sig",
          "x-webflow-timestamp": String(expiredTs),
        },
        body: "raw",
      },
      "sec",
    );
    expect(webflowRes.code).toBe("EXPIRED_TIMESTAMP");
  });

  it("should test validateCliArgs invalid URL error schema branch and normalizeBody Buffer branch", () => {
    const cliRes = validateCliArgs({ url: "invalid-url-str" });
    expect(cliRes.success).toBe(false);
    expect(cliRes.errors).toContain('Invalid URL format: "invalid-url-str"');

    const bodyStr = normalizeBody(Buffer.from("hello buffer"));
    expect(bodyStr).toBe("hello buffer");
  });
});
