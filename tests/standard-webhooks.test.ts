import { describe, expect, it } from "vitest";
import { verifyStandardWebhooks } from "../src/entries/standard-webhooks.js";
import { verifyWebhook, WebhookErrorCode } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

// Reference vector from the Svix / Standard Webhooks libraries' test suites.
const vector = {
  secret: "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
  id: "msg_p5jXN8AQM9LWM0D4loKWxJek",
  timestamp: 1614265330,
  body: '{"test": 2432232314}',
  signature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
};

const vectorRequest = (signature = vector.signature) => ({
  headers: {
    "webhook-id": vector.id,
    "webhook-timestamp": String(vector.timestamp),
    "webhook-signature": signature,
  },
  body: vector.body,
});

describe("standard-webhooks", () => {
  it("verifies the reference vector", async () => {
    const result = await verifyStandardWebhooks(
      vectorRequest(),
      vector.secret,
      {
        now: vector.timestamp,
      },
    );
    expect(result.valid, result.reason).toBe(true);
  });

  it("accepts any of several space-separated signatures (rotation)", async () => {
    const result = await verifyWebhook(
      "standard-webhooks",
      vectorRequest(`v1,bm90X3RoZV9zaWduYXR1cmU= ${vector.signature}`),
      vector.secret,
      { now: vector.timestamp },
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a tampered body, an old timestamp and missing headers", async () => {
    const tampered = { ...vectorRequest(), body: '{"test": 1}' };
    expect(
      (
        await verifyStandardWebhooks(tampered, vector.secret, {
          now: vector.timestamp,
        })
      ).code,
    ).toBe(WebhookErrorCode.INVALID_SIGNATURE);
    expect(
      (await verifyStandardWebhooks(vectorRequest(), vector.secret)).code,
    ).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
    expect(
      (await verifyStandardWebhooks({ headers: {}, body: "{}" }, vector.secret))
        .code,
    ).toBe(WebhookErrorCode.MISSING_HEADER);
  });

  it("dedupes on the signed webhook-id", async () => {
    const hook = await signWebhook("standard-webhooks", {
      secret: vector.secret,
      webhookId: "msg_dedupe",
      payload: { type: "invoice.paid" },
    });
    const { MemoryDedupeStore } = await import("../src/index.js");
    const result = await verifyWebhook(
      "standard-webhooks",
      hook,
      vector.secret,
      {
        dedupeStore: new MemoryDedupeStore(),
      },
    );
    expect(result.dedupeKey).toBe("standard-webhooks:msg_dedupe");
    expect(result.eventType).toBe("invoice.paid");
  });
});
