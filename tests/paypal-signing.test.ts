import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyPayPal, WebhookErrorCode } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

const payload = { id: "WH-EVT-1", event_type: "PAYMENT.CAPTURE.COMPLETED" };
const req = (hook: { headers: Record<string, string>; body: string }) => ({
  headers: hook.headers,
  body: hook.body,
});

describe("signWebhook('paypal')", () => {
  it("round-trips through verifyPayPal with hook.secret and hook.verifyOptions", async () => {
    const hook = await signWebhook("paypal", { payload });
    expect(hook.secret).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(hook.verifyOptions).toEqual({ webhookId: "WH-TEST" });
    expect(hook.headers["paypal-cert-url"]).toBeUndefined();
    const result = await verifyPayPal(
      req(hook),
      hook.secret,
      hook.verifyOptions,
    );
    expect(result.valid, result.reason).toBe(true);
    expect(result.event).toEqual(payload);
  });

  it("signs with a given PKCS#8 key and webhook ID", async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const hook = await signWebhook("paypal", {
      payload,
      webhookId: "WH-MINE",
      privateKey: privateKey
        .export({ type: "pkcs8", format: "pem" })
        .toString(),
    });
    expect(hook.secret).toBe(
      publicKey.export({ type: "spki", format: "pem" }).toString(),
    );
    const result = await verifyPayPal(req(hook), hook.secret, {
      webhookId: "WH-MINE",
    });
    expect(result.valid, result.reason).toBe(true);
  });

  it("fails for the wrong webhook ID, a tampered body, or an old timestamp", async () => {
    const hook = await signWebhook("paypal", { payload });
    expect(
      (await verifyPayPal(req(hook), hook.secret, { webhookId: "WH-OTHER" }))
        .valid,
    ).toBe(false);
    expect(
      (
        await verifyPayPal(
          { ...req(hook), body: hook.body + " " },
          hook.secret,
          hook.verifyOptions,
        )
      ).valid,
    ).toBe(false);

    const old = await signWebhook("paypal", {
      payload,
      timestamp: Math.floor(Date.now() / 1000) - 4 * 86_400,
    });
    const result = await verifyPayPal(req(old), old.secret, old.verifyOptions);
    expect(result.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("rejects a malformed privateKey", async () => {
    await expect(signWebhook("paypal", { privateKey: "nope" })).rejects.toThrow(
      /PKCS#8/,
    );
  });

  it("leaves verifyOptions undefined for other providers", async () => {
    const hook = await signWebhook("stripe", { secret: "whsec_x" });
    expect(hook.verifyOptions).toBeUndefined();
  });
});
