import { describe, expect, it } from "vitest";
import { verifyVercel } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Vercel Webhook Verifier", () => {
  // Vector: hex HMAC-SHA1 of the raw body.
  const secret = "vercel_secret";
  const body =
    '{"id":"evt_1","type":"deployment.succeeded","createdAt":1700000000000,"payload":{"deployment":{"id":"dpl_1"}}}';
  const headers = {
    "x-vercel-signature": "121fc49dd29b913bbb19ad65e8dc00f569f5f73c",
  };

  it("verifies a known-good signature", async () => {
    const result = await verifyVercel({ headers, body }, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("deployment.succeeded");
    expect(result.event?.payload).toEqual({ deployment: { id: "dpl_1" } });
  });

  it("rejects a wrong secret, a modified body and a missing header", async () => {
    expect((await verifyVercel({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyVercel(
          { headers, body: body.replace("dpl_1", "dpl_2") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifyVercel({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("vercel", { secret, payload: { id: "e" } });
    expect((await verifyVercel(hook, secret)).valid).toBe(true);
  });
});
