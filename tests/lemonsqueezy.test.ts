import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyLemonSqueezy } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("LemonSqueezy Webhook Verifier", () => {
  const secret = "lemon_secret_key_888";
  const body = JSON.stringify({ meta: { event_name: "order_created" } });

  it("should verify valid LemonSqueezy signature", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = bytesToHex(hmac);

    const req = {
      headers: { "x-signature": signature },
      body,
    };

    const result = await verifyLemonSqueezy(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("lemonsqueezy");
  });

  it("should reject missing signature header", async () => {
    const req = { headers: {}, body };
    const result = await verifyLemonSqueezy(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("MISSING_HEADER");
  });
});
