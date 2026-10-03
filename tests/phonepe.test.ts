import { describe, expect, it } from "vitest";
import { verifyPhonePe } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("PhonePe Webhook Verifier", () => {
  // Vector: SHA-256 of "merchant_user:merchant_pass" from PhonePe's pg-sdk-node
  // (CommonUtils.calculateSha256), which validateCallback() compares against.
  const secret = "merchant_user:merchant_pass";
  const authorization =
    "a9f681f3fd8ea362ca967eec2d22abdb5dfd61d15bb7f9c4530b03ae8a7b7aa6";
  const body = JSON.stringify({
    event: "checkout.order.completed",
    type: "CHECKOUT_ORDER_COMPLETED",
    payload: { orderId: "OMO123", state: "COMPLETED" },
  });

  it("verifies a known-good authorization hash", async () => {
    const result = await verifyPhonePe(
      { headers: { authorization }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    // `event` wins over the deprecated `type`.
    expect(result.eventType).toBe("checkout.order.completed");
    expect(result.event?.payload).toEqual({
      orderId: "OMO123",
      state: "COMPLETED",
    });
  });

  it("accepts an uppercase hash and a SHA256 prefix", async () => {
    const result = await verifyPhonePe(
      {
        headers: { authorization: `SHA256 ${authorization.toUpperCase()}` },
        body,
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects wrong credentials", async () => {
    const result = await verifyPhonePe(
      { headers: { authorization }, body },
      "merchant_user:other",
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects a secret that is not username:password", async () => {
    const result = await verifyPhonePe(
      { headers: { authorization }, body },
      "just-a-password",
    );
    expect(result.code).toBe("INVALID_SECRET");
  });

  it("rejects a missing authorization header", async () => {
    const result = await verifyPhonePe({ headers: {}, body }, secret);
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("phonepe", {
      secret,
      payload: { event: "x" },
    });
    expect(hook.headers.authorization).toBe(authorization);
    expect((await verifyPhonePe(hook, secret)).valid).toBe(true);
  });
});
