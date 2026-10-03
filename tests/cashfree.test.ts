import { describe, expect, it } from "vitest";
import { verifyCashfree } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Cashfree Webhook Verifier", () => {
  // Vector: base64 HMAC-SHA256 of `<timestamp><body>`, as Cashfree's cashfree-pg SDK
  // (PGVerifyWebhookSignature) computes it.
  const secret = "cf_secret_key";
  const timestampMs = "1704047400000";
  const body =
    '{"data":{"order":{"order_id":"order_1"}},"event_time":"2024-01-01T00:00:00+05:30","type":"PAYMENT_SUCCESS_WEBHOOK"}';
  const signature = "cg+pAcE/sNlK2iaVEHZM9ML2Voa6kB1h8C8jBMRNNC8=";
  const now = 1704047400;
  const headers = {
    "x-webhook-signature": signature,
    "x-webhook-timestamp": timestampMs,
  };

  it("verifies a known-good signature", async () => {
    const result = await verifyCashfree({ headers, body }, secret, { now });
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("PAYMENT_SUCCESS_WEBHOOK");
    expect(result.event?.data).toEqual({ order: { order_id: "order_1" } });
  });

  it("rejects a wrong secret", async () => {
    const result = await verifyCashfree({ headers, body }, "other", { now });
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects a modified body", async () => {
    const result = await verifyCashfree(
      { headers, body: body.replace("order_1", "order_2") },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects missing headers", async () => {
    const result = await verifyCashfree(
      { headers: { "x-webhook-signature": signature }, body },
      secret,
    );
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("rejects a non-numeric timestamp", async () => {
    const result = await verifyCashfree(
      { headers: { ...headers, "x-webhook-timestamp": "soon" }, body },
      secret,
    );
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("rejects an expired timestamp and honours tolerance: 0", async () => {
    const expired = await verifyCashfree({ headers, body }, secret, {
      now: now + 600,
    });
    expect(expired.code).toBe("EXPIRED_TIMESTAMP");

    const unchecked = await verifyCashfree({ headers, body }, secret, {
      now: now + 600,
      tolerance: 0,
    });
    expect(unchecked.valid).toBe(true);
  });

  it("round-trips signWebhook with a millisecond timestamp", async () => {
    const hook = await signWebhook("cashfree", {
      secret,
      payload: { type: "PAYMENT_SUCCESS_WEBHOOK" },
      timestamp: now,
    });
    expect(hook.headers["x-webhook-timestamp"]).toBe(timestampMs);
    const result = await verifyCashfree(hook, secret, { now });
    expect(result.valid).toBe(true);
  });
});
