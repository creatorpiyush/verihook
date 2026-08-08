import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyShopify } from "../src/index.js";
import { bytesToBase64 } from "../src/utils/encoding.js";

describe("Shopify Webhook Verifier", () => {
  const secret = "shpss_shopify_secret_key";
  const body = JSON.stringify({ id: 123456, email: "customer@example.com" });

  it("should verify valid Shopify base64 signature", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const base64Sig = bytesToBase64(hmac);

    const req = {
      headers: { "x-shopify-hmac-sha256": base64Sig },
      body,
    };

    const result = await verifyShopify(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("shopify");
  });

  it("should fail on missing header", async () => {
    const result = await verifyShopify({ headers: {}, body }, secret);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Missing "x-shopify-hmac-sha256" header');
  });
});
