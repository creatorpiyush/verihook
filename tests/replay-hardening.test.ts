import crypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { computeCrc32 } from "../src/core/crypto.js";
import {
  MemoryDedupeStore,
  verifyLinear,
  verifyMeta,
  verifyPayPal,
  verifyWebhook,
  WebhookErrorCode,
} from "../src/index.js";

const now = Math.floor(Date.now() / 1000);

describe("PayPal transmission time", () => {
  const webhookId = "WH-1";
  const body = JSON.stringify({ id: "WH-EVT-1" });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();

  function req(time: string) {
    const sig = crypto
      .createSign("RSA-SHA256")
      .update(`tx_1|${time}|${webhookId}|${computeCrc32(body)}`)
      .sign(privateKey, "base64");
    return {
      headers: {
        "paypal-transmission-id": "tx_1",
        "paypal-transmission-time": time,
        "paypal-transmission-sig": sig,
      },
      body,
    };
  }

  it("rejects a delivery older than the 3-day retry window", async () => {
    const old = new Date((now - 4 * 86_400) * 1000).toISOString();
    const result = await verifyPayPal(req(old), pem, { webhookId });
    expect(result.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("accepts a 2-day-old retry by default, and honours a tighter tolerance", async () => {
    const twoDays = new Date((now - 2 * 86_400) * 1000).toISOString();
    expect((await verifyPayPal(req(twoDays), pem, { webhookId })).valid).toBe(
      true,
    );
    const tight = await verifyPayPal(req(twoDays), pem, {
      webhookId,
      tolerance: 300,
    });
    expect(tight.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("rejects an unparseable transmission time", async () => {
    const result = await verifyPayPal(req("not-a-date"), pem, { webhookId });
    expect(result.code).toBe(WebhookErrorCode.MISSING_HEADER);
  });
});

describe("Linear webhookTimestamp", () => {
  const secret = "lin_wh_secret";
  const req = (payload: object) => {
    const body = JSON.stringify(payload);
    return {
      headers: {
        "linear-signature": crypto
          .createHmac("sha256", secret)
          .update(body)
          .digest("hex"),
      },
      body,
    };
  };

  it("rejects a signed body older than 60 seconds", async () => {
    const result = await verifyLinear(
      req({ webhookTimestamp: (now - 120) * 1000 }),
      secret,
    );
    expect(result.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("accepts a fresh body and reports its timestamp", async () => {
    const result = await verifyLinear(
      req({ webhookTimestamp: now * 1000 }),
      secret,
    );
    expect(result).toMatchObject({ valid: true, timestamp: now });
  });

  it("still accepts bodies without webhookTimestamp", async () => {
    expect((await verifyLinear(req({ action: "create" }), secret)).valid).toBe(
      true,
    );
  });
});

describe("verifyWebhook body limit", () => {
  const bigRequest = (bytes: number) =>
    new Request("http://localhost/hook", {
      method: "POST",
      headers: { "linear-signature": "00" },
      body: "a".repeat(bytes),
    });

  it("rejects a Fetch Request body over the 2MB default", async () => {
    const result = await verifyWebhook(
      "linear",
      bigRequest(2 * 1024 * 1024 + 1),
      "s",
    );
    expect(result.code).toBe(WebhookErrorCode.PAYLOAD_TOO_LARGE);
  });

  it("honours options.maxBodySize", async () => {
    const result = await verifyWebhook("linear", bigRequest(11), "s", {
      maxBodySize: 10,
    });
    expect(result.code).toBe(WebhookErrorCode.PAYLOAD_TOO_LARGE);
  });
});

describe("default dedupe TTL", () => {
  it("records keys for 24 hours", async () => {
    const secret = "lin";
    const body = JSON.stringify({ id: "evt_ttl" });
    const store = new MemoryDedupeStore();
    const spy = vi.spyOn(store, "hasOrSet");
    await verifyWebhook(
      "linear",
      {
        headers: {
          "linear-signature": crypto
            .createHmac("sha256", secret)
            .update(body)
            .digest("hex"),
        },
        body,
      },
      secret,
      { dedupeStore: store },
    );
    expect(spy).toHaveBeenCalledWith("linear:evt_ttl", 86_400_000);
  });
});

describe("Meta signature downgrade", () => {
  it("does not fall back to SHA-1 when a SHA-256 signature is present", async () => {
    const secret = "meta_secret";
    const body = JSON.stringify({ object: "page" });
    const sha1 = crypto.createHmac("sha1", secret).update(body).digest("hex");
    const result = await verifyMeta(
      {
        headers: {
          "x-hub-signature-256": `sha256=${"0".repeat(64)}`,
          "x-hub-signature": `sha1=${sha1}`,
        },
        body,
      },
      secret,
    );
    expect(result.valid).toBe(false);
  });
});
