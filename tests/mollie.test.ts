import { describe, expect, it } from "vitest";
import { verifyMollie } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Mollie Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of the raw body (Mollie next-gen webhooks).
  const secret = "mollie_secret";
  const body =
    '{"resource":"event","id":"event_GvJ8WHrp5isUdRub9CJyH","type":"payment-link.paid","entityId":"pl_qng5gbbv8NAZ5gpM5ZYgx","createdAt":"2024-12-16T15:57:04.0Z"}';
  const signature =
    "sha256=999cae541f09d311286b55ee4efd32a652ce735e76be8116624777e72e9963ce";

  it("verifies a known-good signature", async () => {
    const result = await verifyMollie(
      { headers: { "x-mollie-signature": signature }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("payment-link.paid");
    expect(result.event?.entityId).toBe("pl_qng5gbbv8NAZ5gpM5ZYgx");
  });

  it("accepts either signature during secret rotation", async () => {
    const stale = `sha256=${"0".repeat(64)}`;
    for (const value of [`${stale}, ${signature}`, [signature, stale]]) {
      const result = await verifyMollie(
        { headers: { "x-mollie-signature": value }, body },
        secret,
      );
      expect(result.valid).toBe(true);
    }
  });

  it("rejects a wrong secret and a modified body", async () => {
    const headers = { "x-mollie-signature": signature };
    expect((await verifyMollie({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (await verifyMollie({ headers, body: body.replace("paid", "x") }, secret))
        .code,
    ).toBe("INVALID_SIGNATURE");
  });

  it("rejects a missing signature header", async () => {
    const result = await verifyMollie({ headers: {}, body }, secret);
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("mollie", { secret, payload: { id: "e" } });
    expect((await verifyMollie(hook, secret)).valid).toBe(true);
  });
});
