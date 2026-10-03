import { describe, expect, it } from "vitest";
import { verifyCheckout } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Checkout.com Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of the raw body, keyed with the signature key.
  const secret = "cko_key";
  const body =
    '{"id":"evt_az5sblvku4ge3dwpztvyizgcau","type":"payment_approved","created_on":"2024-01-01T00:00:00Z","data":{"id":"pay_1"}}';
  const signature =
    "c60edad3a800d421eb5b1a8231fea3069d4a3ea9cf33c7898a6b57b4f338427e";

  it("verifies a known-good signature", async () => {
    const result = await verifyCheckout(
      { headers: { "Cko-Signature": signature }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("payment_approved");
    expect(result.event?.id).toBe("evt_az5sblvku4ge3dwpztvyizgcau");
  });

  it("rejects a wrong secret and a modified body", async () => {
    const headers = { "cko-signature": signature };
    expect((await verifyCheckout({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyCheckout(
          { headers, body: body.replace("pay_1", "pay_2") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
  });

  it("rejects a missing signature header", async () => {
    const result = await verifyCheckout({ headers: {}, body }, secret);
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("checkout", {
      secret,
      payload: { id: "e" },
    });
    expect((await verifyCheckout(hook, secret)).valid).toBe(true);
  });
});
